package common

import (
	"crypto/sha256"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
)

const (
	COSE_SIGN1_CONTEXT = "Signature1"
	ALG_ES256          = -7
	ALG_PS256          = -37
)

type CWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected CWTHeader
	Payload     []byte
	Signature   []byte
}

type CWTHeader struct {
	Alg int    `cbor:"1,keyasint,omitempty"`
	KID []byte `cbor:"4,keyasint,omitempty"`
}

type CWTPayload struct {
	Issuer         string `cbor:"1,keyasint"`
	ExpirationTime int64  `cbor:"4,keyasint"`
	IssuedAt       int64  `cbor:"6,keyasint"`

	HCert *HealthCertificate `cbor:"-260,keyasint"`
}

type HealthCertificate struct {
	DGCv1 cbor.RawMessage `cbor:"1,keyasint"`
}

func SerializeAndHashForSignature(protectedHeaderCbor, unprotectedHeaderCbor, payloadCbor []byte) (hash []byte, err error) {
	// Gather, serialize and hash the data that is or needs to be signed
	toHash := []interface{}{
		COSE_SIGN1_CONTEXT,
		protectedHeaderCbor,
		unprotectedHeaderCbor,
		payloadCbor,
	}

	serializedForSigning, err := cbor.Marshal(toHash)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR serialize for hash that is signed/verified", 0)
	}

	hashArr := sha256.Sum256(serializedForSigning)
	hash = hashArr[:]

	return hash, nil
}

func UnmarshalCWTPayload(payloadCbor []byte) (*CWTPayload, error) {
	var payload *CWTPayload
	err := cbor.Unmarshal(payloadCbor, &payload)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal CWT payload", 0)
	}

	return payload, nil
}
