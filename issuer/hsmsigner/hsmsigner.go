package hsmsigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	issuercommon "github.com/minvws/nl-covid19-coronacheck-hcert/issuer/common"
	"math/big"
)

type HSMSigner struct {
	ctx       *crypto11.Context
	usageKeys map[string]*hsmKey
}

type Configuration struct {
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
	usageKeys := map[string]*hsmKey{}
	for _, kd := range config.KeyDescriptions {
		// Load certificate for key
		cert, kid, err := issuercommon.LoadDSCCertificateFile(kd.CertificatePath)
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

		// Load HSM keypair
		keypair, err := ctx.FindKeyPair([]byte{byte(kd.KeyID)}, []byte(kd.KeyLabel))
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not find key due to error", 0)
		}
		if keypair == nil {
			return nil, errors.Errorf("Could not find key with id %d and label '%s'", kd.KeyID, kd.KeyLabel)
		}

		// TODO: VerificationError out when we confirm this works
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
