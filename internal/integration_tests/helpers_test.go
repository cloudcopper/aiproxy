//go:build integration

package integration_tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
)

// ruleFromServer constructs a Rule from an httptest.Server URL.
// Parses the URL to extract scheme, host, and port so the rule only matches
// that specific test server (not others on the same host).
func ruleFromServer(t *testing.T, id, method, serverURL string) reqrules.Rule {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("ruleFromServer: invalid URL %q: %v", serverURL, err)
	}
	port, _ := strconv.Atoi(u.Port())
	return reqrules.Rule{
		ID:     id,
		Method: method,
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Port:   port,
	}
}

// generateTestCA creates a self-signed CA certificate and private key for use
// in tests that require TLS bumping.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateTestCA: generate key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generateTestCA: generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Test CA"}, CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("generateTestCA: create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("generateTestCA: parse certificate: %v", err)
	}

	return cert, key
}
