package common

import "github.com/fxamacker/cbor/v2"

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
