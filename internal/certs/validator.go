package certs

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// validate performs comprehensive certificate validation.
func (m *Manager) validate(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	// Check expiration
	if err := m.validateExpiration(cert); err != nil {
		return err
	}

	// Check CA constraints
	if err := m.validateCAConstraints(cert); err != nil {
		return err
	}

	// Check key usage
	if err := m.validateKeyUsage(cert); err != nil {
		return err
	}

	// Verify key pair matches
	if err := m.validateKeyPair(cert, key); err != nil {
		return err
	}

	return nil
}

// validateExpiration checks certificate validity period.
func (m *Manager) validateExpiration(cert *x509.Certificate) error {
	now := time.Now()

	if now.After(cert.NotAfter) {
		return fmt.Errorf("ca certificate expired on %s", cert.NotAfter.Format(time.RFC3339))
	}

	if now.Before(cert.NotBefore) {
		return fmt.Errorf("ca certificate not yet valid until %s", cert.NotBefore.Format(time.RFC3339))
	}

	// Warn if expiring soon (within 30 days)
	if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		slog.Warn("ca certificate expires soon", "expires", cert.NotAfter)
	}

	return nil
}

// validateCAConstraints checks BasicConstraints and IsCA flag.
func (m *Manager) validateCAConstraints(cert *x509.Certificate) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return errors.New("certificate is not a valid ca certificate (missing BasicConstraints or IsCA=false)")
	}
	return nil
}

// validateKeyUsage checks KeyUsage for CertSign capability.
func (m *Manager) validateKeyUsage(cert *x509.Certificate) error {
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("certificate cannot sign certificates (missing KeyUsageCertSign)")
	}
	return nil
}

// validateKeyPair checks that private key matches certificate public key.
func (m *Manager) validateKeyPair(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("unexpected certificate public key type: %T", cert.PublicKey)
	}

	if !certPub.Equal(&key.PublicKey) {
		return errors.New("private key does not match certificate public key")
	}

	return nil
}

// checkFilePermissions validates private key file has secure permissions.
// This is a warning-only check, not fatal.
func (m *Manager) checkFilePermissions() {
	info, err := os.Stat(m.keyPath)
	if err != nil {
		slog.Warn("cannot check private key file permissions", "path", m.keyPath, "error", err)
		return
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		slog.Warn("ca private key has insecure permissions (should be 0600)",
			"path", m.keyPath,
			"permissions", fmt.Sprintf("%04o", perm),
		)
	}
}
