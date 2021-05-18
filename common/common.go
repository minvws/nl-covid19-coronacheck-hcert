package common

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
)

const (
	ALG_ES256 = -7
	ALG_PS256 = -37
)

type CWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected CWTHeader
	Payload     []byte
	Signature   []byte
}

type CWTHeader struct {
	Alg int    `cbor:"1,keyasint"`
	Kid []byte `cbor:"4,keyasint"`
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

func UnmarshalCWTPayload(payloadCbor []byte) (*CWTPayload, error) {
	var payload *CWTPayload
	err := cbor.Unmarshal(payloadCbor, payload)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal CWT payload", 0)
	}

	return payload, nil
}
