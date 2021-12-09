package localsigner

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	issuercommon "github.com/minvws/nl-covid19-coronacheck-hcert/issuer/common"
	"os"
)

type LocalSigner struct {
	usageKeys map[string]*localKey
}

type Configuration struct {
	KeyDescriptions []*KeyDescription
}

type KeyDescription struct {
	KeyUsage        string
	CertificatePath string
	KeyPath         string
}

type localKey struct {
	kid         []byte
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
}

func New(config *Configuration) (*LocalSigner, error) {
	// Load every key
	usageKeys := map[string]*localKey{}
	for _, kd := range config.KeyDescriptions {
		cert, kid, err := issuercommon.LoadDSCCertificateFile(kd.CertificatePath)
		if err != nil {
			msg := fmt.Sprintf("Could not load certificate file '%s'", kd.CertificatePath)
			return nil, errors.WrapPrefix(err, msg, 0)
		}

		// Load key
		privKey, err := loadPEMKeyFile(kd.KeyPath)
		if err != nil {
			msg := fmt.Sprintf("Could not read PEM key file %s", kd.KeyPath)
			return nil, errors.WrapPrefix(err, msg, 0)
		}

		usageKeys[kd.KeyUsage] = &localKey{
			kid:         kid,
			certificate: cert,
			privateKey:  privKey,
		}
	}

	return &LocalSigner{
		usageKeys: usageKeys,
	}, nil
}

func (ls *LocalSigner) GetKID(keyUsage string) ([]byte, error) {
	// Get key for this usage
	key, ok := ls.usageKeys[keyUsage]
	if !ok {
		return nil, errors.Errorf("Could not find key for signing for usage %s", keyUsage)
	}

	return key.kid, nil
}

func (ls *LocalSigner) Sign(keyUsage string, hash []byte) ([]byte, error) {
	// Get key for this usage
	key, ok := ls.usageKeys[keyUsage]
	if !ok {
		return nil, errors.Errorf("Could not find key for signing for usage %s", keyUsage)
	}

	r, s, err := ecdsa.Sign(rand.Reader, key.privateKey, hash)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not sign hash", 0)
	}

	signature := common.CanonicalSignatureBytes(r, s, key.privateKey.Params())
	return signature, nil
}

func loadPEMKeyFile(keyPath string) (*ecdsa.PrivateKey, error) {
	pemKeyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	pemKeyBlock, _ := pem.Decode(pemKeyBytes)
	if pemKeyBlock == nil || pemKeyBlock.Type != "EC PRIVATE KEY" {
		return nil, errors.Errorf("Could not parse PEM as EC key")
	}

	key, err := x509.ParseECPrivateKey(pemKeyBlock.Bytes)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not parse key inside PEM", 0)
	}

	return key, nil
}
