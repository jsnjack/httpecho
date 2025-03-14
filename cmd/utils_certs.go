package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func ExtractCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		item, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		format := "%+19s: %s\n"
		fmt.Printf(format, "found certificate", item.Subject)
		fmt.Printf(format, "issuer", item.Issuer)
		fmt.Printf(format, "expires in", fmt.Sprintf("%.0f days\n", time.Until(item.NotAfter).Hours()/24))

		if item.NotAfter.Before(time.Now()) {
			return nil, fmt.Errorf("the certificate has expired on %v", item.NotAfter)
		}
		if item.NotBefore.After(time.Now()) {
			return nil, fmt.Errorf("the certificate is valid after %v", item.NotBefore)
		}
		certs = append(certs, item)
	}
	return certs, nil
}

func ExtractPrivateKey(data []byte) (crypto.PrivateKey, error) {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") || len(block.Headers) != 0 {
			continue
		}

		item, err := ParsePrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return item, nil
	}
	return nil, fmt.Errorf("private key not found")
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func ParsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key")
}

func ReadCert(filename string) ([]byte, error) {
	var data []byte
	if filename == "" {
		return nil, fmt.Errorf("provide certificate file")
	}
	_, err := os.Stat(filename)
	if err == nil {
		data, err = os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, err
}
