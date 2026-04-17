package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewManager verifies constructor creates manager with correct paths.
// Note this test does not perform filesystem operations, just checks struct initialization.
func TestNewManager(t *testing.T) {
	tests := []struct {
		name          string
		certPath      string
		keyPath       string
		insecureCerts bool
	}{
		{
			name:          "absolute paths",
			certPath:      "/tmp/certs/ca-cert.pem",
			keyPath:       "/tmp/certs/ca-key.pem",
			insecureCerts: false,
		},
		{
			name:          "with insecure flag",
			certPath:      "/data/cert.pem",
			keyPath:       "/data/key.pem",
			insecureCerts: true,
		},
		{
			name:          "relative paths",
			certPath:      "certs/ca-cert.pem",
			keyPath:       "certs/ca-key.pem",
			insecureCerts: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)

			m := NewManager(tt.certPath, tt.keyPath, tt.insecureCerts)

			is.Equal(tt.certPath, m.certPath)
			is.Equal(tt.keyPath, m.keyPath)
			is.Equal(tt.insecureCerts, m.insecureCerts)
			is.Nil(m.cert)
			is.Nil(m.key)
		})
	}
}

// TestInitialize_GenerateNew verifies certificate generation when no files exist.
func TestInitialize_GenerateNew(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ctx := context.Background()

	// Create temporary directory
	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")

	// Create certs directory (now required before Initialize)
	must.NoError(os.MkdirAll(certsDir, 0750))

	certPath := filepath.Join(certsDir, "ca-cert.pem")
	keyPath := filepath.Join(certsDir, "ca-key.pem")

	m := NewManager(certPath, keyPath, false)
	err := m.Initialize(ctx)
	must.NoError(err)

	// Verify certificate and key are populated
	must.NotNil(m.Certificate())
	must.NotNil(m.PrivateKey())

	// Verify certificate properties
	cert := m.Certificate()
	is.Equal("aiproxy self-signed ca", cert.Subject.CommonName)
	is.Equal([]string{"aiproxy ca"}, cert.Subject.Organization)
	is.True(cert.IsCA)
	is.True(cert.BasicConstraintsValid)
	is.Equal(0, cert.MaxPathLen)
	is.True(cert.MaxPathLenZero)
	is.Equal(x509.KeyUsageCertSign|x509.KeyUsageCRLSign, cert.KeyUsage)

	// Verify validity period (10 years)
	now := time.Now()
	is.True(cert.NotBefore.Before(now) || cert.NotBefore.Equal(now))
	is.True(cert.NotAfter.After(now))
	// Check roughly 10 years (allow 1 day tolerance for clock skew)
	expectedExpiry := now.AddDate(10, 0, 0)
	is.WithinDuration(expectedExpiry, cert.NotAfter, 24*time.Hour)

	// Verify key algorithm is ECDSA P-256
	key := m.PrivateKey()
	is.Equal(elliptic.P256(), key.Curve)

	// Verify public key in cert matches private key
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	must.True(ok)
	is.True(certPub.Equal(&key.PublicKey))

	// Verify files were created
	is.FileExists(m.certPath)
	is.FileExists(m.keyPath)

	// Verify file permissions
	certInfo, err := os.Stat(m.certPath)
	must.NoError(err)
	is.Equal(os.FileMode(0644), certInfo.Mode().Perm())

	keyInfo, err := os.Stat(m.keyPath)
	must.NoError(err)
	is.Equal(os.FileMode(0600), keyInfo.Mode().Perm())
}

// TestInitialize_LoadExisting verifies loading existing valid certificates.
func TestInitialize_LoadExisting(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ctx := context.Background()

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")

	// Create certs directory (now required before Initialize)
	must.NoError(os.MkdirAll(certsDir, 0750))

	certPath := filepath.Join(certsDir, "ca-cert.pem")
	keyPath := filepath.Join(certsDir, "ca-key.pem")

	// Generate certificate first
	m1 := NewManager(certPath, keyPath, false)
	err := m1.Initialize(ctx)
	must.NoError(err)

	origSerial := m1.Certificate().SerialNumber

	// Create new manager and load existing certificates
	m2 := NewManager(certPath, keyPath, false)
	err = m2.Initialize(ctx)
	must.NoError(err)

	// Verify same certificate was loaded
	is.Equal(origSerial, m2.Certificate().SerialNumber)
	is.Equal("aiproxy self-signed ca", m2.Certificate().Subject.CommonName)
}

// TestInitialize_InconsistentState verifies error when only cert or key exists.
func TestInitialize_InconsistentState(t *testing.T) {
	tests := []struct {
		name        string
		createCert  bool
		createKey   bool
		wantErrText string
	}{
		{
			name:        "certificate exists but key missing",
			createCert:  true,
			createKey:   false,
			wantErrText: "certificate exists but key is missing",
		},
		{
			name:        "key exists but certificate missing",
			createCert:  false,
			createKey:   true,
			wantErrText: "key exists but certificate is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			must := require.New(t)
			ctx := context.Background()

			tmpDir := t.TempDir()
			certsDir := filepath.Join(tmpDir, "certs")

			// Create directory
			err := os.MkdirAll(certsDir, 0755)
			must.NoError(err)

			// Create only one file
			certPath := filepath.Join(certsDir, "ca-cert.pem")
			keyPath := filepath.Join(certsDir, "ca-key.pem")

			if tt.createCert {
				err = os.WriteFile(certPath, []byte("fake cert"), 0644)
				must.NoError(err)
			}
			if tt.createKey {
				err = os.WriteFile(keyPath, []byte("fake key"), 0600)
				must.NoError(err)
			}

			// Initialize should fail
			m := NewManager(certPath, keyPath, false)
			err = m.Initialize(ctx)
			is.Error(err)
			is.Contains(err.Error(), tt.wantErrText)
		})
	}
}

// TestCertificate_BeforeInitialize verifies getters return nil before Initialize.
func TestCertificate_BeforeInitialize(t *testing.T) {
	is := assert.New(t)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "certs", "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "certs", "ca-key.pem")
	m := NewManager(certPath, keyPath, false)

	is.Nil(m.Certificate())
	is.Nil(m.PrivateKey())
}

// TestFileExists checks fileExists helper function.
func TestFileExists(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "exists.txt")
	err := os.WriteFile(existingFile, []byte("test"), 0644)
	must.NoError(err)

	is.True(fileExists(existingFile))
	is.False(fileExists(filepath.Join(tmpDir, "does-not-exist.txt")))
}
