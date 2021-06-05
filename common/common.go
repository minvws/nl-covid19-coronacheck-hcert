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

// FindIssuerPkFunc must return a pk of type *ecdsa.PublicKey or *rsa.PublicKey
// Due to potential (intentional) kid collisions, more than one public key can be returned
type FindIssuerPkFunc func(kid []byte) (pk []interface{}, err error)

type CWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected CWTHeader
	Payload     []byte
	Signature   []byte
}

type CWTHeader struct {
	// KID is a pointer to a byte slice, so the entire sturct can be compared with an empty value
	KID *[]byte `cbor:"4,keyasint,omitempty"`
	Alg int     `cbor:"1,keyasint,omitempty"`
}

type CWTPayload struct {
	Issuer         string `cbor:"1,keyasint"`
	ExpirationTime int64  `cbor:"4,keyasint"`
	IssuedAt       int64  `cbor:"6,keyasint"`

	HCert *RawHealthCertificate `cbor:"-260,keyasint"`
}

type RawHealthCertificate struct {
	DCC cbor.RawMessage `cbor:"1,keyasint"`
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
