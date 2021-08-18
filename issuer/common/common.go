package common

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/go-errors/errors"
	"os"
)

func LoadDSCCertificateFile(certificatePath string) (cert *x509.Certificate, kid []byte, err error) {
	// Read and load certificate file
	pemCertBytes, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, nil, err
	}

	pemCertBlock, _ := pem.Decode(pemCertBytes)
	if pemCertBlock == nil || pemCertBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.Errorf("Could not parse PEM as certificate")
	}

	cert, err = x509.ParseCertificate(pemCertBlock.Bytes)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not parse certificate inside PEM", 0)
	}

	// Calculate KID
	certSum := sha256.Sum256(pemCertBlock.Bytes)
	kid = certSum[0:8]

	return cert, kid, nil
}
