package localsigner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-errors/errors"
	"math/big"
	"os"
)

type DSC struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
}

// LoadDSC doesn't do much sanity checking, as it isn't going to be used in production
func LoadDSC(pemCertPath, pemKeyPath string) (*DSC, error) {
	// Load certificate
	pemCertBytes, err := os.ReadFile(pemCertPath)
	if err != nil {
		msg := fmt.Sprintf("Could not read PEM certificate file %s", pemCertPath)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	pemCertBlock, _ := pem.Decode(pemCertBytes)
	if pemCertBlock == nil || pemCertBlock.Type != "CERTIFICATE" {
		return nil, errors.Errorf("Could not parse PEM file %s as certificate", pemCertPath)
	}

	cert, err := x509.ParseCertificate(pemCertBlock.Bytes)
	if err != nil {
		msg := fmt.Sprintf("Could not parse certificate inside PEM file %s", pemCertPath)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	// Load key
	pemKeyBytes, err := os.ReadFile(pemKeyPath)
	if err != nil {
		msg := fmt.Sprintf("Could not read PEM key file %s", pemKeyPath)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	pemKeyBlock, _ := pem.Decode(pemKeyBytes)
	if pemKeyBlock == nil || pemKeyBlock.Type != "EC PRIVATE KEY" {
		return nil, errors.Errorf("Could not parse PEM file %s as EC key", pemKeyPath)
	}

	key, err := x509.ParseECPrivateKey(pemKeyBlock.Bytes)
	if err != nil {
		msg := fmt.Sprintf("Could not parse key inside PEM file %s", pemKeyPath)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	return &DSC{
		Certificate: cert,
		Key:         key,
	}, nil
}

// Sign doesn't do much sanity checking ,as it isn't going to be used in production
func Sign(dsc *DSC, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, dsc.Key, hash)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not sign hash", 0)
	}

	keyByteSize := dsc.Key.Curve.Params().BitSize / 8
	signature := append(i2osp(r, keyByteSize), i2osp(s, keyByteSize)...)

	return signature, nil
}

func i2osp(b *big.Int, n int) []byte {
	ostr := b.Bytes()
	if n > len(ostr) {
		var buf bytes.Buffer
		buf.Write(make([]byte, n-len(ostr))) // prepend 0s
		buf.Write(ostr)
		return buf.Bytes()
	} else {
		return ostr[:n]
	}
}
