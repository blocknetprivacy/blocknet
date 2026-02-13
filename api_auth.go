package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const cookieFilename = "api.cookie"

// generateToken creates a 32-byte random hex token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// writeCookie writes the auth token to <dataDir>/api.cookie with 0600 perms.
func writeCookie(dataDir, token string) error {
	path := filepath.Join(dataDir, cookieFilename)
	return os.WriteFile(path, []byte(token), 0600)
}

// deleteCookie removes the cookie file.
func deleteCookie(dataDir string) {
	if err := os.Remove(filepath.Join(dataDir, cookieFilename)); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove API cookie file: %v", err)
	}
}

// authMiddleware rejects requests that don't carry a valid Bearer token.
func authMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provided := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
