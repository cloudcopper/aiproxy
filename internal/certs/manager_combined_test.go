package certs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitialize_LoadCombinedFile verifies loading certificate and key from single file.
func TestInitialize_LoadCombinedFile(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ctx := context.Background()

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	// Create valid certificate
	cert, key := createValidTestCertificate(t)
	combinedPath := filepath.Join(certsDir, "combined.pem")
	writeCombinedPEM(t, combinedPath, cert, key)

	// Both paths point to same file
	m := NewManager(combinedPath, combinedPath, false)
	err := m.Initialize(ctx)
	must.NoError(err)

	// Verify certificate and key loaded
	must.NotNil(m.Certificate())
	must.NotNil(m.PrivateKey())
	is.Equal(cert.SerialNumber, m.Certificate().SerialNumber)
	is.True(key.PublicKey.Equal(&m.PrivateKey().PublicKey))
}

// TestLoadCombined_ValidFormat verifies combined file with cert first, key second.
func TestLoadCombined_ValidFormat(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	cert, key := createValidTestCertificate(t)
	combinedPath := filepath.Join(certsDir, "combined.pem")
	writeCombinedPEM(t, combinedPath, cert, key)

	m := NewManager(combinedPath, combinedPath, false)
	err := m.loadCombined()
	must.NoError(err)

	is.Equal(cert.SerialNumber, m.cert.SerialNumber)
	is.True(key.PublicKey.Equal(&m.key.PublicKey))
}

// TestLoadCombined_KeyFirst verifies error when key comes before cert.
func TestLoadCombined_KeyFirst(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	cert, key := createValidTestCertificate(t)
	combinedPath := filepath.Join(certsDir, "combined.pem")

	// Write key first, then cert (wrong order)
	keyPEM, err := encodeKeyPEM(key)
	must.NoError(err)
	certPEM := encodeCertificatePEM(cert)
	combined := append(keyPEM, certPEM...)
	must.NoError(os.WriteFile(combinedPath, combined, 0600))

	m := NewManager(combinedPath, combinedPath, false)
	err = m.loadCombined()
	is.Error(err)
	is.Contains(err.Error(), "expected CERTIFICATE block first")
}

// TestLoadCombined_MissingCertificate verifies error when cert block missing.
func TestLoadCombined_MissingCertificate(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	_, key := createValidTestCertificate(t)
	combinedPath := filepath.Join(certsDir, "combined.pem")

	// Write only key
	keyPEM, err := encodeKeyPEM(key)
	must.NoError(err)
	must.NoError(os.WriteFile(combinedPath, keyPEM, 0600))

	m := NewManager(combinedPath, combinedPath, false)
	err = m.loadCombined()
	is.Error(err)
	is.Contains(err.Error(), "expected CERTIFICATE block first")
}

// TestLoadCombined_MissingKey verifies error when key block missing.
func TestLoadCombined_MissingKey(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	cert, _ := createValidTestCertificate(t)
	combinedPath := filepath.Join(certsDir, "combined.pem")

	// Write only certificate
	certPEM := encodeCertificatePEM(cert)
	must.NoError(os.WriteFile(combinedPath, certPEM, 0600))

	m := NewManager(combinedPath, combinedPath, false)
	err := m.loadCombined()
	is.Error(err)
	is.Contains(err.Error(), "expected EC PRIVATE KEY block second")
}

// TestLoadCombined_InvalidCertificate verifies error when cert block is malformed.
func TestLoadCombined_InvalidCertificate(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	combinedPath := filepath.Join(certsDir, "combined.pem")

	// Write invalid certificate PEM (valid base64 but invalid certificate structure)
	invalidPEM := `-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEabcdefghijklmnopqrstuvwxyz1234567890ABCDEFG=
-----END EC PRIVATE KEY-----
`
	must.NoError(os.WriteFile(combinedPath, []byte(invalidPEM), 0600))

	m := NewManager(combinedPath, combinedPath, false)
	err := m.loadCombined()
	is.Error(err)
	is.Contains(err.Error(), "failed to parse certificate")
}

// TestLoadCombined_InvalidKey verifies error when key block is malformed.
func TestLoadCombined_InvalidKey(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	cert, _ := createValidTestCertificate(t)
	combinedPath := filepath.Join(certsDir, "combined.pem")

	// Write valid cert but invalid key (valid base64 but invalid key structure)
	certPEM := encodeCertificatePEM(cert)
	invalidKeyPEM := []byte(`-----BEGIN EC PRIVATE KEY-----
AAAA
-----END EC PRIVATE KEY-----
`)
	combined := append(certPEM, invalidKeyPEM...)
	must.NoError(os.WriteFile(combinedPath, combined, 0600))

	m := NewManager(combinedPath, combinedPath, false)
	err := m.loadCombined()
	is.Error(err)
	is.Contains(err.Error(), "failed to parse private key")
}

// TestIsCombinedFile verifies detection of combined file mode.
func TestIsCombinedFile(t *testing.T) {
	tests := []struct {
		name     string
		certPath string
		keyPath  string
		want     bool
	}{
		{
			name:     "same path - combined",
			certPath: "/certs/combined.pem",
			keyPath:  "/certs/combined.pem",
			want:     true,
		},
		{
			name:     "different paths - separate",
			certPath: "/certs/ca-cert.pem",
			keyPath:  "/certs/ca-key.pem",
			want:     false,
		},
		{
			name:     "different directories",
			certPath: "/certs1/cert.pem",
			keyPath:  "/certs2/cert.pem",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)

			m := NewManager(tt.certPath, tt.keyPath, false)
			got := m.isCombinedFile()
			is.Equal(tt.want, got)
		})
	}
}

// TestLoadCombined_ValidationSuccess verifies validation runs on combined file.
func TestLoadCombined_ValidationSuccess(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ctx := context.Background()

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	cert, key := createValidTestCertificate(t)
	combinedPath := filepath.Join(certsDir, "combined.pem")
	writeCombinedPEM(t, combinedPath, cert, key)

	m := NewManager(combinedPath, combinedPath, false)
	err := m.Initialize(ctx)
	must.NoError(err)

	// Should pass validation
	is.NotNil(m.Certificate())
	is.NotNil(m.PrivateKey())
}

// TestLoadCombined_InsecureCerts verifies insecure mode works with combined files.
func TestLoadCombined_InsecureCerts(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ctx := context.Background()

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	// Create expired certificate
	cert, key := createExpiredCertificate(t)
	combinedPath := filepath.Join(certsDir, "combined.pem")
	writeCombinedPEM(t, combinedPath, cert, key)

	// Without insecure flag - should fail
	m1 := NewManager(combinedPath, combinedPath, false)
	err := m1.Initialize(ctx)
	is.Error(err)
	is.Contains(err.Error(), "expired")

	// With insecure flag - should succeed
	m2 := NewManager(combinedPath, combinedPath, true)
	err = m2.Initialize(ctx)
	is.NoError(err)
	is.NotNil(m2.Certificate())
	is.NotNil(m2.PrivateKey())
}

// TestInitialize_SeparateFilesBackwardCompatibility verifies separate files still work.
func TestInitialize_SeparateFilesBackwardCompatibility(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ctx := context.Background()

	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	must.NoError(os.MkdirAll(certsDir, 0750))

	cert, key := createValidTestCertificate(t)
	certPath := filepath.Join(certsDir, "ca-cert.pem")
	keyPath := filepath.Join(certsDir, "ca-key.pem")

	writeCertificatePEM(t, certPath, cert)
	writeKeyPEM(t, keyPath, key)

	// Different paths - should use separate file loading
	m := NewManager(certPath, keyPath, false)
	err := m.Initialize(ctx)
	must.NoError(err)

	is.NotNil(m.Certificate())
	is.NotNil(m.PrivateKey())
	is.Equal(cert.SerialNumber, m.Certificate().SerialNumber)
}
