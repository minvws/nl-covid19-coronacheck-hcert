package issuer

import (
	"crypto/sha256"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
)

const (
	COSE_SIGN1_CONTEXT = "Signature1"
	COSE_SIGN1_TAG     = 18
)

type ToSerialize struct {
	KeyIdentifier []byte

	Issuer         string
	IssuedAt       int64
	ExpirationTime int64

	DGC map[string]interface{}
}

// SerializeForSigning intentionally doesn't support all the different COSE bells and whistles,
// and only does one thing well: serialize electronic health certificates for ECDSA / SHA-256 signing
func Serialize(toSerialize *ToSerialize) (unsigned *common.SignedCWT, hash []byte, err error) {
	// Build and serialize the protected header
	header := &common.CWTHeader{
		Alg: common.ALG_ES256,
		Kid: toSerialize.KeyIdentifier,
	}

	headerCbor, err := cbor.Marshal(header)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR marshal CWT header", 0)
	}

	// Serialize DGC separately, and then the rest of the payload
	dgcCbor, err := cbor.Marshal(toSerialize.DGC)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR marshal DGC", 0)
	}

	payload := &common.CWTPayload{
		Issuer:         toSerialize.Issuer,
		ExpirationTime: toSerialize.ExpirationTime,
		IssuedAt:       toSerialize.IssuedAt,
		HCert: &common.HealthCertificate{
			DGCv1: dgcCbor,
		},
	}

	payloadCbor, err := cbor.Marshal(payload)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR marshal CWT payload", 0)
	}

	// Gather, serialize and hash the data that needs to be signed
	toSign := []interface{}{
		COSE_SIGN1_CONTEXT,
		headerCbor,
		payloadCbor,
	}

	serializedForSigning, err := cbor.Marshal(toSign)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR serialize for signing", 0)
	}

	hashArr := sha256.Sum256(serializedForSigning)
	hash = hashArr[:]

	// Build the yet unsigned CWT
	unsigned = &common.SignedCWT{
		Protected: headerCbor,
		Payload:   payloadCbor,
	}

	return unsigned, hash, nil
}

func FinalizeCWT(unsigned *common.SignedCWT, signature []byte) ([]byte, error) {
	signedCWT := &common.SignedCWT{
		Protected: unsigned.Protected,
		Payload:   unsigned.Payload,
		Signature: signature,
	}

	signedCWTCbor, err := cbor.Marshal(cbor.Tag{
		Number:  COSE_SIGN1_TAG,
		Content: signedCWT,
	})
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR serialize signed CWT", 0)
	}

	return signedCWTCbor, nil
}
