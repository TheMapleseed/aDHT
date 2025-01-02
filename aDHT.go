// Package dht provides a complete distributed hash table implementation
// with network partition tolerance, state machine replication, and
// cryptographic security using only Go standard libraries.
package dht

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Protocol and cryptographic constants
const (
	// Protocol versioning
	ProtocolVersion = 1
	MaxMessageSize  = 1 << 20 // 1MB
	MaxPayloadSize  = 1 << 19 // 512KB

	// Cryptographic sizes (in bytes)
	KeySize    = 32 // AES-256
	NonceSize  = 12 // GCM requirement
	TagSize    = 16 // GCM tag
	NodeIDSize = 32 // SHA-256 size

	// Network timeouts
	DialTimeout  = 10 * time.Second
	WriteTimeout = 5 * time.Second
	ReadTimeout  = 5 * time.Second

	// Consensus timeouts
	ConsensusTimeout  = 30 * time.Second
	HeartbeatInterval = 1 * time.Second

	// Network partition parameters
	MaxPartitionTime = 5 * time.Minute
	MergeTimeout     = 30 * time.Second

	// Discovery parameters
	DiscoveryInterval = 1 * time.Minute
	MaxPeers          = 64
)

// Protocol errors
var (
	ErrPartitioned      = errors.New("network partitioned")
	ErrMergeInProgress  = errors.New("merge in progress")
	ErrConsensusTimeout = errors.New("consensus timeout")
	ErrInvalidState     = errors.New("invalid state")
	ErrCryptoFailure    = errors.New("cryptographic operation failed")
	ErrInvalidMessage   = errors.New("invalid message format")
	ErrInvalidSignature = errors.New("invalid signature")
)

// NodeID uniquely identifies a node
type NodeID [NodeIDSize]byte

// Node represents a DHT node
type Node struct {
	ID       NodeID
	addr     *net.TCPAddr
	state    NetworkState
	lastSeen time.Time

	// Cryptographic context
	gcm      cipher.AEAD
	nonceCtr uint64
	hmacKey  [KeySize]byte

	// TLS configuration
	tlsConfig *tls.Config
	certPool  *x509.CertPool

	// Connection management
	listener  net.Listener
	peers     sync.Map
	peerCount int32

	// State machine
	stateMachine *StateMachine

	// Consensus
	term     uint64
	votedFor NodeID
	leader   NodeID
	isLeader bool

	// Network partition management
	partitionID []byte
	mergeState  *mergeState

	// Message handling
	msgCh chan *Message
	cmdCh chan *Command
	errCh chan error

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// NetworkState represents node state
type NetworkState uint8

const (
	StateNormal NetworkState = iota
	StatePartitioned
	StateMerging
)

// Message types for protocol communication
type MessageType uint8

const (
	TypeDiscover MessageType = iota
	TypeDiscoverResponse
	TypeHeartbeat
	TypeVoteRequest
	TypeVoteResponse
	TypeAppendEntries
	TypeAppendResponse
	TypePartition
	TypeMergeRequest
	TypeMergeAccept
	TypeMergeComplete
)

// Message represents a protocol message
type Message struct {
	Version   uint8
	Type      MessageType
	Sender    NodeID
	Receiver  NodeID
	Term      uint64
	Timestamp int64
	Nonce     [NonceSize]byte
	Payload   []byte
	MAC       [sha256.Size]byte
}

// Command represents a state machine command
type Command struct {
	Operation string
	Key       []byte
	Value     []byte
	Timestamp int64
}

// StateMachine implements replicated state
type StateMachine struct {
	state     sync.Map
	log       []LogEntry
	commitIdx uint64
	lastIdx   uint64
	mu        sync.RWMutex
}

// LogEntry represents a state machine log entry
type LogEntry struct {
	Term      uint64
	Index     uint64
	Command   *Command
	Timestamp int64
}

// NewNode initializes a new DHT node
func NewNode(key []byte, cert *tls.Certificate) (*Node, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", KeySize, len(key))
	}

	// Initialize AES-GCM with timing irregularity
	block, err := initAESWithJitter(key)
	if err != nil {
		return nil, fmt.Errorf("AES initialization failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM initialization failed: %w", err)
	}

	// Generate node ID with timing irregularity
	id, err := generateNodeID()
	if err != nil {
		return nil, fmt.Errorf("node ID generation failed: %w", err)
	}

	// Initialize TLS configuration
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		Certificates:             []tls.Certificate{*cert},
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	node := &Node{
		ID:           id,
		state:        StateNormal,
		gcm:          gcm,
		tlsConfig:    tlsConfig,
		stateMachine: NewStateMachine(),
		msgCh:        make(chan *Message, 1024),
		cmdCh:        make(chan *Command, 1024),
		errCh:        make(chan error, 64),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Initialize HMAC key
	if err := node.deriveHMACKey(key); err != nil {
		return nil, err
	}

	return node, nil
}

// Start initializes the node and starts background processes
func (n *Node) Start(addr string) error {
	// Start TLS listener
	listener, err := tls.Listen("tcp", addr, n.tlsConfig)
	if err != nil {
		return fmt.Errorf("listener setup failed: %w", err)
	}
	n.listener = listener

	// Start background processes
	go n.acceptConnections()
	go n.discoveryProcess()
	go n.heartbeatProcess()
	go n.consensusProcess()

	return nil
}

// acceptConnections handles incoming connections
func (n *Node) acceptConnections() {
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			select {
			case n.errCh <- fmt.Errorf("accept failed: %w", err):
			case <-n.ctx.Done():
				return
			}
			continue
		}

		go n.handleConnection(conn.(*tls.Conn))
	}
}

// handleConnection processes a peer connection
func (n *Node) handleConnection(conn *tls.Conn) {
	defer conn.Close()

	// Perform timing-irregular handshake
	if err := n.performHandshake(conn); err != nil {
		return
	}

	// Process messages
	for {
		msg, err := n.readMessage(conn)
		if err != nil {
			return
		}

		if err := n.handleMessage(msg, conn); err != nil {
			return
		}
	}
}

// discoveryProcess handles peer discovery
func (n *Node) discoveryProcess() {
	ticker := time.NewTicker(DiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := n.discoverPeers(); err != nil {
				select {
				case n.errCh <- fmt.Errorf("discovery failed: %w", err):
				case <-n.ctx.Done():
					return
				}
			}
		case <-n.ctx.Done():
			return
		}
	}
}

// consensusProcess manages consensus operations
func (n *Node) consensusProcess() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if n.isLeader {
				if err := n.sendHeartbeat(); err != nil {
					// Handle error but continue operation
					continue
				}
			}
		case cmd := <-n.cmdCh:
			if err := n.processCommand(cmd); err != nil {
				select {
				case n.errCh <- fmt.Errorf("command processing failed: %w", err):
				case <-n.ctx.Done():
					return
				}
			}
		case <-n.ctx.Done():
			return
		}
	}
}

// Cryptographic Operations

// initAESWithJitter initializes AES with timing irregularity
func initAESWithJitter(key []byte) (cipher.Block, error) {
	// Add random timing jitter
	jitter := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, jitter); err != nil {
		return nil, err
	}

	expandedKey := make([]byte, len(key))
	for i := range key {
		// Irregular timing operation
		time.Sleep(time.Duration(jitter[i%32]) * time.Microsecond)
		expandedKey[i] = key[i]
	}

	return aes.NewCipher(expandedKey)
}

// deriveHMACKey derives the HMAC key with timing irregularity
func (n *Node) deriveHMACKey(key []byte) error {
	jitter := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, jitter); err != nil {
		return err
	}

	h := hmac.New(sha256.New, key)
	info := []byte("hmac-key-derivation-v1")

	for i, b := range info {
		time.Sleep(time.Duration(jitter[i%32]) * time.Microsecond)
		h.Write([]byte{b})
	}

	copy(n.hmacKey[:], h.Sum(nil))
	return nil
}

// generateNodeID creates a node ID with timing irregularity
func generateNodeID() (NodeID, error) {
	var id NodeID
	randBytes := make([]byte, NodeIDSize*2)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		return id, err
	}

	h := sha256.New()
	for i := 0; i < NodeIDSize; i++ {
		time.Sleep(time.Duration(randBytes[i]) * time.Microsecond)
		h.Write(randBytes[i : i+1])
	}

	copy(id[:], h.Sum(nil))
	return id, nil
}

// encrypt performs timing-irregular encryption
func (n *Node) encrypt(msg *Message) ([]byte, error) {
	// Generate nonce with atomic counter
	var nonce [NonceSize]byte
	ctr := atomic.AddUint64(&n.nonceCtr, 1)
	binary.BigEndian.PutUint64(nonce[4:], ctr)

	// Add timing jitter
	jitterBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, jitterBytes); err != nil {
		return nil, err
	}

	// Serialize message with jitter
	serialized := make([]byte, len(msg.Payload))
	for i, b := range msg.Payload {
		time.Sleep(time.Duration(jitterBytes[i%32]) * time.Microsecond)
		serialized[i] = b
	}

	ciphertext := n.gcm.Seal(nil, nonce[:], serialized, nil)
	return ciphertext, nil
}

// Decrypt performs timing-irregular decryption
func (n *Node) decrypt(ciphertext []byte) ([]byte, error) {
	// Generate nonce with atomic counter
	var nonce [NonceSize]byte
	ctr := atomic.AddUint64(&n.nonceCtr, 1)
	binary.BigEndian.PutUint64(nonce[4:], ctr)

	// Add timing jitter
	jitterBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, jitterBytes); err != nil {
		return nil, err
	}

	// Decrypt the ciphertext
	plaintext, err := n.gcm.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Deserialize with timing jitter
	deserialized := make([]byte, len(plaintext))
	for i, b := range plaintext {
		time.Sleep(time.Duration(jitterBytes[i%32]) * time.Microsecond)
		deserialized[i] = b
	}

	return deserialized, nil
}
