package hsmsigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"math/big"
	"os"
)

type HSMSigner struct {
	ctx       *crypto11.Context
	usageKeys map[string]*hsmKey
}

type SignerConfiguration struct {
	PKCS11ModulePath string
	TokenLabel       string
	Pin              string

	KeyDescriptions []*KeyDescription
}

type KeyDescription struct {
	CertificatePath string
	KeyUsage        string
	KeyID           int
	KeyLabel        string

	keypair crypto11.Signer
	kid     []byte
}

type hsmKey struct {
	kid     []byte
	keypair crypto11.Signer
	params  *elliptic.CurveParams
}

type signatureSerialization struct {
	R *big.Int
	S *big.Int
}

func New(config *SignerConfiguration) (*HSMSigner, error) {
	// Create HSM context
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       config.PKCS11ModulePath,
		TokenLabel: config.TokenLabel,
		Pin:        config.Pin,
	})
	if err != nil {
		msg := fmt.Sprintf(
			"Could not create pkcs11 context, wrong module path (%s) or token label (%s)",
			config.PKCS11ModulePath, config.TokenLabel,
		)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	// Load every key
	usageKeys := map[string]*hsmKey{}
	for _, kd := range config.KeyDescriptions {
		// Load certificate for key
		cert, pemCertBlock, err := loadCertificate(kd.CertificatePath)
		if err != nil {
			msg := fmt.Sprintf("Could not load certificate file '%s'", kd.CertificatePath)
			return nil, errors.WrapPrefix(err, msg, 0)
		}

		var certificatePk *ecdsa.PublicKey
		switch tpk := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			certificatePk = tpk
		default:
			return nil, errors.Errorf("Unsupported key type for '%s'", kd.CertificatePath)
		}

		// Calculate KID
		certSum := sha256.Sum256(pemCertBlock.Bytes)
		kid := certSum[0:8]

		// Load HSM keypair
		keypair, err := ctx.FindKeyPair([]byte{byte(kd.KeyID)}, []byte(kd.KeyLabel))
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not find key due to error", 0)
		}
		if keypair == nil {
			return nil, errors.Errorf("Could not find key with id %d and label '%s'", kd.KeyID, kd.KeyLabel)
		}

		// TODO: Error out when we confirm this works
		if !certificatePk.Equal(keypair.Public()) {
			fmt.Println("WARNING, REPORT THIS: HSM public key doesn't match certificate. This will be fatal in a future version")
		}

		// Put hsmKey into usage lookup
		usageKeys[kd.KeyUsage] = &hsmKey{
			kid:     kid,
			keypair: keypair,
			params:  keypair.Public().(*ecdsa.PublicKey).Params(),
		}
	}

	return &HSMSigner{
		ctx:       ctx,
		usageKeys: usageKeys,
	}, nil
}

func (hs *HSMSigner) Sign(keyUsage string, hash []byte) ([]byte, error) {
	// Get key for this usage
	key, ok := hs.usageKeys[keyUsage]
	if !ok {
		return nil, errors.Errorf("Could not find key for signing for usage %s", keyUsage)
	}

	// Do the actual signing
	signatureASN1, err := key.keypair.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create signature", 0)
	}

	// Get the signature components and convert it to a CWT signature
	components := &signatureSerialization{}
	_, err = asn1.Unmarshal(signatureASN1, components)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not ASN1 unmarshal signature", 0)
	}

	signature := common.ConvertSignatureComponents(components.R, components.S, key.params)
	return signature, nil
}

func (hs *HSMSigner) GetKID(keyUsage string) (kid []byte, err error) {
	key, ok := hs.usageKeys[keyUsage]
	if !ok {
		return nil, errors.Errorf("Could not find key for KID for usage %s", keyUsage)
	}

	return key.kid, nil
}

func loadCertificate(certificatePath string) (*x509.Certificate, *pem.Block, error) {
	pemCertBytes, err := os.ReadFile(certificatePath)
	if err != nil {
		msg := fmt.Sprintf("Could not read PEM certificate file")
		return nil, nil, errors.WrapPrefix(err, msg, 0)
	}

	pemCertBlock, _ := pem.Decode(pemCertBytes)
	if pemCertBlock == nil || pemCertBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.Errorf("Could not parse PEM as certificate")
	}

	cert, err := x509.ParseCertificate(pemCertBlock.Bytes)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not parse certificate inside PEM", 0)
	}

	return cert, pemCertBlock, nil
}
