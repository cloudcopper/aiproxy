package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

)

// Manager handles CA certificate lifecycle: generation, loading, and validation.
type Manager struct {
	certPath      string
	keyPath       string
	insecureCerts bool
	cert          *x509.Certificate
	key           *ecdsa.PrivateKey
}

// NewManager creates a certificate manager for the specified certificate and key file paths.
// If insecureCerts is true, validation errors are downgraded to warnings.
func NewManager(certPath, keyPath string, insecureCerts bool) *Manager {
	return &Manager{
		certPath:      certPath,
		keyPath:       keyPath,
		insecureCerts: insecureCerts,
	}
}

// Initialize loads or generates the CA certificate.
// Returns an error if certificate validation fails (unless insecureCerts is true).
func (m *Manager) Initialize(ctx context.Context) error {
	// Check if using combined file mode (both paths point to same file)
	if m.isCombinedFile() {
		combinedExists := fileExists(m.certPath)
		if combinedExists {
			slog.Info("loading ca certificate from combined file", "path", m.certPath)
			return m.loadCombined()
		}
		// Combined file doesn't exist - generate separate files
		slog.Info("generating new ca certificate (separate files)", "cert", m.certPath, "key", m.keyPath)
		return m.generateAndSave()
	}

	// Separate file mode
	certExists := fileExists(m.certPath)
	keyExists := fileExists(m.keyPath)

	// Case 1: Both files exist - load and validate
	if certExists && keyExists {
		slog.Info("loading existing ca certificate", "cert", m.certPath, "key", m.keyPath)
		return m.loadSeparate()
	}

	// Case 2: Neither file exists - generate new CA
	if !certExists && !keyExists {
		slog.Info("generating new ca certificate", "cert", m.certPath, "key", m.keyPath)
		return m.generateAndSave()
	}

	// Case 3: Only one file exists - inconsistent state
	if certExists {
		return fmt.Errorf("inconsistent certificate state: certificate exists but key is missing (cert=%s, key=%s)", m.certPath, m.keyPath)
	}
	if keyExists {
		return fmt.Errorf("inconsistent certificate state: key exists but certificate is missing (cert=%s, key=%s)", m.certPath, m.keyPath)
	}
	panic("unreachable code")
}

// Certificate returns the loaded CA certificate.
// Must call Initialize() first.
func (m *Manager) Certificate() *x509.Certificate {
	return m.cert
}

// PrivateKey returns the loaded CA private key.
// Must call Initialize() first.
func (m *Manager) PrivateKey() *ecdsa.PrivateKey {
	return m.key
}

// isCombinedFile returns true if cert and key paths point to the same file.
func (m *Manager) isCombinedFile() bool {
	return m.certPath == m.keyPath
}

// loadCombined loads certificate and key from a single combined PEM file.
// Expected format: Certificate block first, then private key block.
func (m *Manager) loadCombined() error {
	// Read combined file
	pemData, err := os.ReadFile(m.certPath)
	if err != nil {
		return fmt.Errorf("failed to read combined certificate file: %w", err)
	}

	// Parse first PEM block (expect CERTIFICATE)
	certBlock, remaining := pem.Decode(pemData)
	if certBlock == nil {
		return errors.New("failed to decode PEM from combined file")
	}
	if certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("expected CERTIFICATE block first in combined file, got %s", certBlock.Type)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate from combined file: %w", err)
	}

	// Parse second PEM block (expect EC PRIVATE KEY)
	keyBlock, _ := pem.Decode(remaining)
	if keyBlock == nil {
		return errors.New("expected EC PRIVATE KEY block second in combined file, but no second block found")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		return fmt.Errorf("expected EC PRIVATE KEY block second in combined file, got %s", keyBlock.Type)
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key from combined file: %w", err)
	}

	// Validate certificate and key
	if err := m.validate(cert, key); err != nil {
		if !m.insecureCerts {
			return fmt.Errorf("certificate validation failed: %w", err)
		}
		slog.Warn("certificate validation failed but continuing due to --insecure-certs", "error", err)
	}

	// Store loaded certificate and key
	m.cert = cert
	m.key = key

	slog.Info("successfully loaded ca certificate from combined file",
		"path", m.certPath,
		"subject", cert.Subject.CommonName,
		"expiry", cert.NotAfter.Format(time.RFC3339))

	return nil
}

// loadSeparate loads certificate and key from separate PEM files and validates them.
func (m *Manager) loadSeparate() error {
	// Read certificate file
	certPEM, err := os.ReadFile(m.certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// Parse certificate PEM
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Read private key file
	keyPEM, err := os.ReadFile(m.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse private key PEM
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to decode private key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse EC private key: %w", err)
	}

	// Validate certificate and key
	if err := m.validate(cert, key); err != nil {
		if !m.insecureCerts {
			return fmt.Errorf("certificate validation failed: %w", err)
		}
		slog.Warn("certificate validation failed but continuing due to --insecure-certs", "error", err)
	}

	// Check file permissions (warning only, not fatal)
	m.checkFilePermissions()

	m.cert = cert
	m.key = key

	slog.Info("ca certificate loaded successfully",
		"subject", cert.Subject.CommonName,
		"expires", cert.NotAfter,
		"serial", cert.SerialNumber,
	)

	return nil
}

// generateAndSave generates a new CA certificate and saves it to disk.
func (m *Manager) generateAndSave() error {
	cert, key, err := m.generateCA()
	if err != nil {
		return fmt.Errorf("failed to generate ca certificate: %w", err)
	}

	if err := m.saveCA(cert, key); err != nil {
		return fmt.Errorf("failed to save ca certificate: %w", err)
	}

	m.cert = cert
	m.key = key

	slog.Info("generated new ca certificate",
		"subject", cert.Subject.CommonName,
		"expires", cert.NotAfter,
		"serial", cert.SerialNumber,
	)

	return nil
}
