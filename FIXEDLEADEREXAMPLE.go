package dht

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"
)

// FixedLeaderID holds the ID of the fixed leader
var FixedLeaderID NodeID

// ConsensusTimeout defines the timeout for leader checks and fault tolerance
const ConsensusTimeout = 30 * time.Second

// Node represents a DHT node with a fixed leader mechanism
type Node struct {
	ID       NodeID
	leader   NodeID // Fixed leader ID that is locked to a specific node
	term     uint64
	isLeader bool
	peers    sync.Map
	msgCh    chan *Message
	cmdCh    chan *Command
	errCh    chan error
	ctx      context.Context
	cancel   context.CancelFunc
}

// Initialize the fixed leader
func SetFixedLeader(leaderID NodeID) {
	FixedLeaderID = leaderID
}

// Initialize the node with either fixed or dynamic leader election
func NewNodeWithFixedLeader(key []byte, cert *tls.Certificate, isFixed bool) (*Node, error) {
	// Initialize node as before
	node, err := NewNode(key, cert)
	if err != nil {
		return nil, err
	}

	// If fixed leader, set the leader to the predefined ID
	if isFixed {
		node.leader = FixedLeaderID
		node.isLeader = node.ID == FixedLeaderID
	}

	return node, nil
}

// consensusProcess is the background process handling leader checking and maintenance
func (n *Node) consensusProcess() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if n.isLeader {
				// The fixed leader always sends heartbeats
				if err := n.sendHeartbeat(); err != nil {
					select {
					case n.errCh <- fmt.Errorf("heartbeat failed: %w", err):
					case <-n.ctx.Done():
						return
					}
				}
			} else if n.leader == FixedLeaderID {
				// If the fixed leader is not the current leader, handle leader synchronization
				if err := n.syncLeader(); err != nil {
					select {
					case n.errCh <- fmt.Errorf("leader sync failed: %w", err):
					case <-n.ctx.Done():
						return
					}
				}
			}
		case <-n.ctx.Done():
			return
		}
	}
}

// syncLeader ensures the fixed leader is in place
func (n *Node) syncLeader() error {
	if n.leader != FixedLeaderID {
		// Check if the fixed leader node is available
		if err := n.checkFixedLeader(); err != nil {
			return err
		}

		// If no fixed leader found, or if it's not the leader, attempt to fix it
		n.leader = FixedLeaderID
		n.isLeader = n.ID == FixedLeaderID
		return nil
	}
	return nil
}

// checkFixedLeader checks if the fixed leader is available in the network
func (n *Node) checkFixedLeader() error {
	// Simulate checking the network for the fixed leader
	// In a real-world scenario, you could ping the leader node or check its health
	if n.leader != FixedLeaderID {
		return errors.New("fixed leader not available")
	}
	return nil
}
