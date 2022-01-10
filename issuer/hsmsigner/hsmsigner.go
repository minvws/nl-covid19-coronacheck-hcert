package hsmsigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	issuercommon "github.com/minvws/nl-covid19-coronacheck-hcert/issuer/common"
	"math/big"
)

type HSMSigner struct {
	ctx       *crypto11.Context
	usageKeys map[string]*Key
}

type Configuration struct {
	PKCS11ModulePath string
	TokenLabel       string
	Pin              string

	UsageKeys map[string]*Key
}

type Key struct {
	CertificatePath string `mapstructure:"certificate-path"`
	KeyIDHex        string `mapstructure:"key-id-hex"`
	KeyLabel        string `mapstructure:"key-label"`

	kid     []byte
	keypair crypto11.Signer
	params  *elliptic.CurveParams
}

type signatureSerialization struct {
	R *big.Int
	S *big.Int
}

func New(config *Configuration) (*HSMSigner, error) {
	// Create HSM context
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       config.PKCS11ModulePath,
		TokenLabel: config.TokenLabel,
		Pin:        config.Pin,
	})
	if err != nil {
		msg := fmt.Sprintf(
			"Could not create pkcs11 context, wrong PIN, module path (%s) or token label (%s)",
			config.PKCS11ModulePath, config.TokenLabel,
		)
		return nil, errors.WrapPrefix(err, msg, 0)
	}

	// Load every key
	for _, key := range config.UsageKeys {
		// Load certificate for key
		cert, kid, err := issuercommon.LoadDSCCertificateFile(key.CertificatePath)
		if err != nil {
			msg := fmt.Sprintf("Could not load certificate file '%s'", key.CertificatePath)
			return nil, errors.WrapPrefix(err, msg, 0)
		}

		var certificatePk *ecdsa.PublicKey
		switch tpk := cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			certificatePk = tpk
		default:
			return nil, errors.Errorf("Unsupported key type for '%s'", key.CertificatePath)
		}

		// Load HSM keypair
		keyID, err := hex.DecodeString(key.KeyIDHex)
		if err != nil {
			msg := fmt.Sprintf("Could not decode key id hex '%s' for label '%s'", key.KeyIDHex, key.KeyLabel)
			return nil, errors.WrapPrefix(err, msg, 0)
		}

		keypair, err := ctx.FindKeyPair(keyID, []byte(key.KeyLabel))
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not find key due to error", 0)
		}
		if keypair == nil {
			return nil, errors.Errorf("Could not find key with id hex '%s' and label '%s'", key.KeyIDHex, key.KeyLabel)
		}

		if !certificatePk.Equal(keypair.Public()) {
			return nil, errors.Errorf("HSM supplied public key with id hex '%s' and label '%s' doesn't match certificate file '%s'.", key.KeyIDHex, key.KeyLabel, key.CertificatePath)
		}

		// Save the gathered information into the key
		key.kid = kid
		key.keypair = keypair
		key.params = keypair.Public().(*ecdsa.PublicKey).Params()
	}

	return &HSMSigner{
		ctx:       ctx,
		usageKeys: config.UsageKeys,
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

	signature := common.CanonicalSignatureBytes(components.R, components.S, key.params)
	return signature, nil
}

func (hs *HSMSigner) GetKID(keyUsage string) (kid []byte, err error) {
	key, ok := hs.usageKeys[keyUsage]
	if !ok {
		return nil, errors.Errorf("Could not find key for KID for usage %s", keyUsage)
	}

	return key.kid, nil
}
