package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateExpiration checks expiration validation logic.
func TestValidateExpiration(t *testing.T) {
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantErr   bool
		errText   string
	}{
		{
			name:      "valid certificate",
			notBefore: time.Now().Add(-24 * time.Hour),
			notAfter:  time.Now().Add(365 * 24 * time.Hour),
			wantErr:   false,
		},
		{
			name:      "expired certificate",
			notBefore: time.Now().Add(-365 * 24 * time.Hour),
			notAfter:  time.Now().Add(-24 * time.Hour),
			wantErr:   true,
			errText:   "expired on",
		},
		{
			name:      "not yet valid",
			notBefore: time.Now().Add(24 * time.Hour),
			notAfter:  time.Now().Add(365 * 24 * time.Hour),
			wantErr:   true,
			errText:   "not yet valid until",
		},
		{
			name:      "expiring soon (29 days)",
			notBefore: time.Now().Add(-24 * time.Hour),
			notAfter:  time.Now().Add(29 * 24 * time.Hour),
			wantErr:   false, // should warn but not error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)

			m := &Manager{}
			cert := &x509.Certificate{
				NotBefore: tt.notBefore,
				NotAfter:  tt.notAfter,
			}

			err := m.validateExpiration(cert)
			if tt.wantErr {
				is.Error(err)
				is.Contains(err.Error(), tt.errText)
				return
			}
			is.NoError(err)
		})
	}
}

// TestValidateCAConstraints checks CA flag validation.
func TestValidateCAConstraints(t *testing.T) {
	tests := []struct {
		name                  string
		basicConstraintsValid bool
		isCA                  bool
		wantErr               bool
	}{
		{
			name:                  "valid CA certificate",
			basicConstraintsValid: true,
			isCA:                  true,
			wantErr:               false,
		},
		{
			name:                  "BasicConstraints invalid",
			basicConstraintsValid: false,
			isCA:                  true,
			wantErr:               true,
		},
		{
			name:                  "IsCA false",
			basicConstraintsValid: true,
			isCA:                  false,
			wantErr:               true,
		},
		{
			name:                  "both invalid",
			basicConstraintsValid: false,
			isCA:                  false,
			wantErr:               true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)

			m := &Manager{}
			cert := &x509.Certificate{
				BasicConstraintsValid: tt.basicConstraintsValid,
				IsCA:                  tt.isCA,
			}

			err := m.validateCAConstraints(cert)
			if tt.wantErr {
				is.Error(err)
				is.Contains(err.Error(), "not a valid ca certificate")
				return
			}
			is.NoError(err)
		})
	}
}

// TestValidateKeyUsage checks KeyUsage validation.
func TestValidateKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		keyUsage x509.KeyUsage
		wantErr  bool
	}{
		{
			name:     "CertSign present",
			keyUsage: x509.KeyUsageCertSign,
			wantErr:  false,
		},
		{
			name:     "CertSign and CRLSign",
			keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			wantErr:  false,
		},
		{
			name:     "missing CertSign",
			keyUsage: x509.KeyUsageCRLSign,
			wantErr:  true,
		},
		{
			name:     "no key usage",
			keyUsage: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)

			m := &Manager{}
			cert := &x509.Certificate{
				KeyUsage: tt.keyUsage,
			}

			err := m.validateKeyUsage(cert)
			if tt.wantErr {
				is.Error(err)
				is.Contains(err.Error(), "cannot sign certificates")
				return
			}
			is.NoError(err)
		})
	}
}

// TestValidateKeyPair checks private key matches certificate public key.
func TestValidateKeyPair(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	// Generate two different key pairs
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(err)

	tests := []struct {
		name    string
		certKey *ecdsa.PrivateKey
		privKey *ecdsa.PrivateKey
		wantErr bool
	}{
		{
			name:    "matching key pair",
			certKey: key1,
			privKey: key1,
			wantErr: false,
		},
		{
			name:    "mismatched key pair",
			certKey: key1,
			privKey: key2,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{}
			cert := &x509.Certificate{
				PublicKey: &tt.certKey.PublicKey,
			}

			err := m.validateKeyPair(cert, tt.privKey)
			if tt.wantErr {
				is.Error(err)
				is.Contains(err.Error(), "does not match")
				return
			}
			is.NoError(err)
		})
	}
}

// TestValidateKeyPair_WrongKeyType checks error for non-ECDSA keys.
func TestValidateKeyPair_WrongKeyType(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(err)

	m := &Manager{}
	// Certificate with wrong public key type (string instead of *ecdsa.PublicKey)
	cert := &x509.Certificate{
		PublicKey: "not an ecdsa key",
	}

	err = m.validateKeyPair(cert, key)
	is.Error(err)
	is.Contains(err.Error(), "unexpected certificate public key type")
}

// TestLoadExisting_InvalidPEM checks handling of corrupted PEM files.
func TestLoadExisting_InvalidPEM(t *testing.T) {
	must := require.New(t)

	// Generate a valid certificate for testing key PEM errors
	validCert, validKey := createValidTestCertificate(t)

	tests := []struct {
		name        string
		setupFiles  func(certPath, keyPath string)
		wantErrText string
	}{
		{
			name: "invalid certificate PEM",
			setupFiles: func(certPath, keyPath string) {
				must.NoError(os.WriteFile(certPath, []byte("not a valid PEM"), 0644))
				writeKeyPEM(t, keyPath, validKey)
			},
			wantErrText: "failed to decode certificate PEM",
		},
		{
			name: "invalid key PEM",
			setupFiles: func(certPath, keyPath string) {
				writeCertificatePEM(t, certPath, validCert)
				must.NoError(os.WriteFile(keyPath, []byte("not a valid PEM"), 0600))
			},
			wantErrText: "failed to decode private key PEM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)

			tmpDir := t.TempDir()
			certsDir := filepath.Join(tmpDir, "certs")
			err := os.MkdirAll(certsDir, 0755)
			must.NoError(err)

			certPath := filepath.Join(certsDir, "ca-cert.pem")
			keyPath := filepath.Join(certsDir, "ca-key.pem")

			tt.setupFiles(certPath, keyPath)

			m := NewManager(certPath, keyPath, false)
			err = m.Initialize(context.Background())
			is.Error(err)
			is.Contains(err.Error(), tt.wantErrText)
		})
	}
}

// TestInsecureCerts_ValidationFailure verifies insecure mode allows invalid certs.
func TestInsecureCerts_ValidationFailure(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	err := os.MkdirAll(certsDir, 0755)
	must.NoError(err)

	// Create expired certificate
	cert, key := createExpiredCertificate(t)
	certPath := filepath.Join(certsDir, "ca-cert.pem")
	keyPath := filepath.Join(certsDir, "ca-key.pem")

	writeCertificatePEM(t, certPath, cert)
	writeKeyPEM(t, keyPath, key)

	// Without insecure flag - should fail
	m1 := NewManager(certPath, keyPath, false)
	err = m1.Initialize(context.Background())
	is.Error(err)
	is.Contains(err.Error(), "expired")

	// With insecure flag - should succeed with warning
	m2 := NewManager(certPath, keyPath, true)
	err = m2.Initialize(context.Background())
	is.NoError(err)
	is.NotNil(m2.Certificate())
	is.NotNil(m2.PrivateKey())
}
