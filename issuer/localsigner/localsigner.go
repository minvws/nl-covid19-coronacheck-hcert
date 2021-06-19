package localsigner

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"os"
)

type LocalSigner struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	kid         []byte
}

type LocalSignerConfiguration struct {
	DSCCertificatePath string
	DSCKeyPath         string
}

// NewFromFile doesn't do much sanity checking, as it isn't going to be used in production
func NewFromFile(pemCertPath, pemKeyPath string) (*LocalSigner, error) {
	// Load certificate
	pemCertBytes, err := os.ReadFile(pemCertPath)
	if err != nil {
		msg := fmt.Sprintf("Could not read PEM certificate file %s", pemCertPath)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	// Load key
	pemKeyBytes, err := os.ReadFile(pemKeyPath)
	if err != nil {
		msg := fmt.Sprintf("Could not read PEM key file %s", pemKeyPath)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	ls, err := New(pemCertBytes, pemKeyBytes)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create local signer", 0)
	}

	return ls, nil
}

// New doesn't do much sanity checking, as it isn't going to be used in production
func New(pemCertBytes, pemKeyBytes []byte) (*LocalSigner, error) {
	// Load certificate
	pemCertBlock, _ := pem.Decode(pemCertBytes)
	if pemCertBlock == nil || pemCertBlock.Type != "CERTIFICATE" {
		return nil, errors.Errorf("Could not parse PEM as certificate")
	}

	cert, err := x509.ParseCertificate(pemCertBlock.Bytes)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not parse certificate inside PEM", 0)
	}

	// Load private key
	pemKeyBlock, _ := pem.Decode(pemKeyBytes)
	if pemKeyBlock == nil || pemKeyBlock.Type != "EC PRIVATE KEY" {
		return nil, errors.Errorf("Could not parse PEM as EC key")
	}

	key, err := x509.ParseECPrivateKey(pemKeyBlock.Bytes)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not parse key inside PEM", 0)
	}

	// Calculate KID
	certSum := sha256.Sum256(pemCertBlock.Bytes)
	kid := certSum[0:8]

	return &LocalSigner{
		certificate: cert,
		key:         key,
		kid:         kid,
	}, nil
}

func (ls *LocalSigner) GetKID(keyUsage string) ([]byte, error) {
	return ls.kid, nil
}

// Sign doesn't do much sanity checking, as it isn't going to be used in production
func (ls *LocalSigner) Sign(keyUsage string, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, ls.key, hash)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not sign hash", 0)
	}

	signature := common.ConvertSignatureComponents(r, s, ls.key.Params())
	return signature, nil
}
