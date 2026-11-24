// Package ca manages the local root CA and on-demand leaf certificates,
// equivalent to Rust's ca module but using Go's crypto/x509.
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arick/hakimi-gop/internal/config"
)

const subjectCN = "hakimi-gop Local CA"

type Authority struct {
	mu      sync.Mutex
	paths   config.Paths
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	leaves  map[string]*tls.Certificate
}

func LoadOrCreate(paths config.Paths) (*Authority, error) {
	if err := paths.Ensure(); err != nil {
		return nil, err
	}
	a := &Authority{paths: paths, leaves: map[string]*tls.Certificate{}}
	certPEM, err := os.ReadFile(paths.CAFile())
	keyPEM, errKey := os.ReadFile(paths.CAKey())
	if err == nil && errKey == nil {
		cert, err := parseCert(certPEM)
		key, err2 := parseKey(keyPEM)
		if err == nil && err2 == nil {
			a.cert, a.key, a.certPEM = cert, key, certPEM
			return a, nil
		}
	}
	if err := a.generate(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Authority) generate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subjectCN, Organization: []string{"hakimi-gop"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	a.cert, a.key = cert, key
	a.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(a.paths.CAFile(), a.certPEM, 0o644); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return os.WriteFile(a.paths.CAKey(), keyPEM, 0o600)
}

func parseCert(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKey(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("unsupported PKCS#8 key type %T", key)
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func (a *Authority) PEM() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.certPEM...)
}

func (a *Authority) Subject() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cert == nil {
		return ""
	}
	return a.cert.Subject.String()
}

func (a *Authority) FingerprintSHA1() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cert == nil {
		return ""
	}
	return fmt.Sprintf("%x", a.cert.RawSubject[:8])
}

// Trusted checks the OS trust store. It is a best-effort probe; MITM can also
// be forced in tests with HAKIMI_GOP_ASSUME_CA=1.
func (a *Authority) Trusted() bool {
	if os.Getenv("HAKIMI_GOP_ASSUME_CA") == "1" {
		return true
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return false
	}
	a.mu.Lock()
	subject := a.cert.RawSubject
	a.mu.Unlock()
	for _, subjectKey := range roots.Subjects() {
		if string(subjectKey) == string(subject) {
			return true
		}
	}
	return false
}

func (a *Authority) Leaf(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if leaf := a.leaves[host]; leaf != nil {
		return leaf, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, 7),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, a.cert.Raw},
		PrivateKey:  key,
	}
	a.leaves[host] = leaf
	return leaf, nil
}

func (a *Authority) TLSConfig(host string) (*tls.Config, error) {
	leaf, err := a.Leaf(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func (a *Authority) Status() map[string]any {
	a.mu.Lock()
	valid := a.cert != nil && time.Now().Before(a.cert.NotAfter)
	subject, fingerprint := "", ""
	if a.cert != nil {
		subject = a.cert.Subject.String()
		fingerprint = fmt.Sprintf("%x", a.cert.RawSubject[:8])
	}
	a.mu.Unlock()
	return map[string]any{
		"present":         valid,
		"trusted":         a.Trusted(),
		"subject":         subject,
		"fingerprintSha1": fingerprint,
		"certificate":     a.paths.CAFile(),
		"valid":           valid,
	}
}

func (a *Authority) Regenerate() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = os.Rename(a.paths.CAFile(), a.paths.CAFile()+".bak")
	_ = os.Rename(a.paths.CAKey(), a.paths.CAKey()+".bak")
	a.leaves = map[string]*tls.Certificate{}
	return a.generate()
}

func (a *Authority) Export(path string) error {
	return os.WriteFile(path, a.PEM(), 0o644)
}

func EnsureDir(path string) error { return os.MkdirAll(filepath.Dir(path), 0o700) }
