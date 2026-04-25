package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// TLSDir returns the TLS directory inside the data dir.
func TLSDir(dataDir string) string {
	return filepath.Join(dataDir, "tls")
}

// TLSCertPath returns the default cert path.
func TLSCertPath(dataDir string) string {
	return filepath.Join(TLSDir(dataDir), "cert.pem")
}

// TLSKeyPath returns the default key path.
func TLSKeyPath(dataDir string) string {
	return filepath.Join(TLSDir(dataDir), "key.pem")
}

// TLSCertsExist checks if self-signed certs already exist.
func TLSCertsExist(dataDir string) bool {
	_, certErr := os.Stat(TLSCertPath(dataDir))
	_, keyErr := os.Stat(TLSKeyPath(dataDir))
	return certErr == nil && keyErr == nil
}

// GenerateSelfSignedCert creates a self-signed TLS certificate and key.
// The cert is valid for localhost, 127.0.0.1, ::1, and any provided extra hosts.
// Validity: 2 years.
func GenerateSelfSignedCert(dataDir string, extraHosts ...string) (certPath, keyPath string, err error) {
	tlsDir := TLSDir(dataDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return "", "", fmt.Errorf("creating TLS directory: %w", err)
	}

	// Generate ECDSA P-256 key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}

	// Serial number
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Plugger"},
			CommonName:   "Plugger Dashboard",
		},
		NotBefore:             now,
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour), // 2 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Add extra hosts (IPs or DNS names)
	for _, h := range extraHosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if h != "" {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Add 0.0.0.0 and common LAN ranges
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("0.0.0.0"))

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("creating certificate: %w", err)
	}

	// Write cert
	certPath = TLSCertPath(dataDir)
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", "", fmt.Errorf("writing cert: %w", err)
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write key
	keyPath = TLSKeyPath(dataDir)
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("writing key: %w", err)
	}
	defer keyFile.Close()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshaling key: %w", err)
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPath, keyPath, nil
}
