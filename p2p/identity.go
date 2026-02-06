// Package p2p implements privacy-focused peer-to-peer networking
package p2p

import (
	"crypto/rand"
	"log"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// IdentityManager handles peer ID generation and rotation
// For privacy, we generate ephemeral identities rather than persistent ones
type IdentityManager struct {
	mu sync.RWMutex

	currentKey  crypto.PrivKey
	currentID   peer.ID
	createdAt   time.Time
	rotationAge time.Duration

	// Path to persist identity (empty = ephemeral)
	persistPath string

	// Callback when identity rotates (node needs to restart connections)
	onRotate func(newKey crypto.PrivKey, newID peer.ID)
}

// IdentityConfig configures identity behavior
type IdentityConfig struct {
	// RotationInterval is how often to rotate identity (0 = never)
	// Recommended: 24 hours for reasonable privacy without too much churn
	RotationInterval time.Duration

	// PersistPath is where to save the identity key (empty = ephemeral)
	// Use this for seed/bootstrap nodes that need stable peer IDs
	PersistPath string

	// OnRotate is called when identity changes
	OnRotate func(newKey crypto.PrivKey, newID peer.ID)
}

// DefaultIdentityConfig returns sensible defaults
func DefaultIdentityConfig() IdentityConfig {
	return IdentityConfig{
		RotationInterval: 24 * time.Hour,
		PersistPath:      "",
		OnRotate:         nil,
	}
}

// NewIdentityManager creates a new identity manager
// If PersistPath is set, loads existing identity or creates and saves a new one
func NewIdentityManager(cfg IdentityConfig) (*IdentityManager, error) {
	var key crypto.PrivKey
	var id peer.ID
	var err error

	// Check for override identity file first
	if home, _ := os.UserHomeDir(); home != "" {
		overridePath := home + "/.blocknet/identity.key"
		if key, id, err = loadIdentity(overridePath); err == nil {
			cfg.PersistPath = overridePath
			cfg.RotationInterval = 0
		}
	}

	if key == nil && cfg.PersistPath != "" {
		// Try to load existing identity
		key, id, err = loadIdentity(cfg.PersistPath)
		if err != nil {
			// Generate new and save
			key, id, err = generateIdentity()
			if err != nil {
				return nil, err
			}
			if err := saveIdentity(cfg.PersistPath, key); err != nil {
				return nil, err
			}
		}
	} else if key == nil {
		// Ephemeral identity
		key, id, err = generateIdentity()
		if err != nil {
			return nil, err
		}
	}

	im := &IdentityManager{
		currentKey:  key,
		currentID:   id,
		createdAt:   time.Now(),
		rotationAge: cfg.RotationInterval,
		persistPath: cfg.PersistPath,
		onRotate:    cfg.OnRotate,
	}

	return im, nil
}

// loadIdentity loads an identity from disk
func loadIdentity(path string) (crypto.PrivKey, peer.ID, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	key, err := crypto.UnmarshalPrivateKey(data)
	if err != nil {
		return nil, "", err
	}

	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, "", err
	}

	return key, id, nil
}

// saveIdentity saves an identity to disk
func saveIdentity(path string, key crypto.PrivKey) error {
	data, err := crypto.MarshalPrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// generateIdentity creates a new Ed25519 keypair for peer identity
func generateIdentity() (crypto.PrivKey, peer.ID, error) {
	// Use Ed25519 for identity (fast, secure, small keys)
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, "", err
	}

	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, "", err
	}

	return priv, id, nil
}

// CurrentIdentity returns the current private key and peer ID
func (im *IdentityManager) CurrentIdentity() (crypto.PrivKey, peer.ID) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.currentKey, im.currentID
}

// CurrentPeerID returns just the current peer ID
func (im *IdentityManager) CurrentPeerID() peer.ID {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.currentID
}

// Age returns how long the current identity has been active
func (im *IdentityManager) Age() time.Duration {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return time.Since(im.createdAt)
}

// ShouldRotate returns true if the identity is older than the rotation interval
func (im *IdentityManager) ShouldRotate() bool {
	if im.rotationAge == 0 {
		return false // Rotation disabled
	}
	im.mu.RLock()
	defer im.mu.RUnlock()
	return time.Since(im.createdAt) > im.rotationAge
}

// Rotate generates a new identity and notifies the callback
// Returns the new peer ID
// Does nothing if rotation is disabled (rotationAge == 0)
func (im *IdentityManager) Rotate() (peer.ID, error) {
	if im.rotationAge == 0 {
		// Rotation disabled (seed node)
		return im.CurrentPeerID(), nil
	}

	newKey, newID, err := generateIdentity()
	if err != nil {
		return "", err
	}

	im.mu.Lock()
	oldID := im.currentID
	im.currentKey = newKey
	im.currentID = newID
	im.createdAt = time.Now()
	callback := im.onRotate
	persistPath := im.persistPath
	im.mu.Unlock()

	// Save to disk if persistence is enabled
	if persistPath != "" {
		if err := saveIdentity(persistPath, newKey); err != nil {
			log.Printf("Warning: failed to save rotated identity: %v", err)
		}
	}

	log.Printf("Identity rotated from %s to %s", oldID, newID)

	// Notify outside the lock to prevent deadlocks
	if callback != nil {
		callback(newKey, newID)
	}

	return newID, nil
}

// StartRotationLoop starts a background goroutine that periodically rotates identity
// Returns a stop function
func (im *IdentityManager) StartRotationLoop() func() {
	if im.rotationAge == 0 {
		// Rotation disabled, return no-op stop function
		return func() {}
	}

	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)

		// Check every 5 minutes if rotation is needed
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if im.ShouldRotate() {
					im.Rotate()
				}
			}
		}
	}()

	return func() {
		close(stop)
		<-done
	}
}

// SetRotationCallback sets the callback for identity rotation
// This is useful if the callback wasn't known at construction time
func (im *IdentityManager) SetRotationCallback(cb func(newKey crypto.PrivKey, newID peer.ID)) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.onRotate = cb
}
