package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arick/hakimi-gop/internal/config"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestImportP12(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Test Imported CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p12, err := pkcs12.Encode(rand.Reader, key, cert, nil, "secret")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.p12")
	if err := os.WriteFile(path, p12, 0o600); err != nil {
		t.Fatal(err)
	}

	paths := config.NewPaths(t.TempDir())
	authority, err := LoadOrCreate(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.ImportP12(path, "secret"); err != nil {
		t.Fatalf("ImportP12: %v", err)
	}
	if got := authority.Subject(); got != cert.Subject.String() {
		t.Fatalf("subject = %q, want %q", got, cert.Subject.String())
	}
	if err := authority.ImportP12(path, "wrong"); err == nil {
		t.Fatal("expected failure with wrong passphrase")
	}

	leaf, err := authority.Leaf("example.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leafCert.Issuer.CommonName != "Test Imported CA" {
		t.Fatalf("leaf issuer = %q", leafCert.Issuer.CommonName)
	}
	if leafCert.Subject.CommonName != "example.com" {
		t.Fatalf("leaf subject = %q", leafCert.Subject.CommonName)
	}
	if _, err := os.Stat(paths.CAFile()); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	if info, err := os.Stat(paths.CAKey()); err != nil {
		t.Fatalf("key file missing: %v", err)
	} else if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("key file permissions too broad: %o", info.Mode().Perm())
	}
}
