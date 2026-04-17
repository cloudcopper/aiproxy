package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Helper: Create an expired certificate for testing.
func createExpiredCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	must := require.New(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	must.NoError(err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Expired Test CA",
		},
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired yesterday
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must.NoError(err)

	cert, err := x509.ParseCertificate(certDER)
	must.NoError(err)

	return cert, key
}

// Helper: Create a valid certificate for testing.
func createValidTestCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	must := require.New(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	must.NoError(err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must.NoError(err)

	cert, err := x509.ParseCertificate(certDER)
	must.NoError(err)

	return cert, key
}

// Helper: Write certificate to PEM file.
func writeCertificatePEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	must := require.New(t)

	certPEM := encodeCertificatePEM(cert)
	must.NoError(os.WriteFile(path, certPEM, 0644))
}

// Helper: Write private key to PEM file.
func writeKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	must := require.New(t)

	keyPEM, err := encodeKeyPEM(key)
	must.NoError(err)
	must.NoError(os.WriteFile(path, keyPEM, 0600))
}

// Helper: Write combined certificate and key to single PEM file.
func writeCombinedPEM(t *testing.T, path string, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	must := require.New(t)

	certPEM := encodeCertificatePEM(cert)
	keyPEM, err := encodeKeyPEM(key)
	must.NoError(err)

	// Combine cert and key PEM (cert first, then key)
	combined := append(certPEM, keyPEM...)
	must.NoError(os.WriteFile(path, combined, 0600))
}
