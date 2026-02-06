package p2p

import (
	"log"

	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// BanGater implements libp2p's ConnectionGater to reject banned peers
type BanGater struct {
	// isBanned checks if a peer is banned
	isBanned func(peer.ID) bool
}

// NewBanGater creates a new connection gater that rejects banned peers
func NewBanGater(checkBan func(peer.ID) bool) *BanGater {
	return &BanGater{isBanned: checkBan}
}

// InterceptPeerDial tests whether we're permitted to dial the peer
func (g *BanGater) InterceptPeerDial(pid peer.ID) bool {
	if g.isBanned == nil {
		return true
	}
	banned := g.isBanned(pid)
	if banned {
		log.Printf("GATER: Blocking dial to banned peer %s", pid.String()[:16])
	}
	return !banned
}

// InterceptAddrDial tests whether we're permitted to dial the address
func (g *BanGater) InterceptAddrDial(pid peer.ID, addr multiaddr.Multiaddr) bool {
	if g.isBanned == nil {
		return true
	}
	return !g.isBanned(pid)
}

// InterceptAccept tests whether incoming connection is allowed
func (g *BanGater) InterceptAccept(n network.ConnMultiaddrs) bool {
	// Can't check peer ID at this stage, allow and check later
	return true
}

// InterceptSecured tests whether a secured connection is allowed
func (g *BanGater) InterceptSecured(dir network.Direction, pid peer.ID, n network.ConnMultiaddrs) bool {
	if g.isBanned == nil {
		return true
	}
	// Block banned peers after handshake
	return !g.isBanned(pid)
}

// InterceptUpgraded tests whether a fully upgraded connection is allowed
func (g *BanGater) InterceptUpgraded(conn network.Conn) (bool, control.DisconnectReason) {
	if g.isBanned == nil {
		return true, 0
	}
	if g.isBanned(conn.RemotePeer()) {
		return false, control.DisconnectReason(1) // Custom reason: banned
	}
	return true, 0
}
