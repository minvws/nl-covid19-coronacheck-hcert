package common

import (
	"crypto/sha256"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
)

type CWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected CWTHeader
	Payload     []byte
	Signature   []byte
}

type CWTHeader struct {
	// KID is a pointer to a byte slice, so the entire struct can be compared with an empty value
	KID *[]byte `cbor:"4,keyasint,omitempty"`
	Alg int     `cbor:"1,keyasint,omitempty"`
}

type CWTPayload struct {
	Issuer         string `cbor:"1,keyasint"`
	ExpirationTime int64  `cbor:"4,keyasint"`
	IssuedAt       int64  `cbor:"6,keyasint"`

	HCert *RawHealthCertificate `cbor:"-260,keyasint"`
}

type cwtPayloadWithFloatTimestamps struct {
	Issuer         string  `cbor:"1,keyasint"`
	ExpirationTime float64 `cbor:"4,keyasint"`
	IssuedAt       float64 `cbor:"6,keyasint"`

	HCert *RawHealthCertificate `cbor:"-260,keyasint"`
}
type RawHealthCertificate struct {
	// Halt unmarshalling here, so CWT verification can take place first
	DCC cbor.RawMessage `cbor:"1,keyasint"`
}

type HealthCertificate struct {
	CredentialVersion int    `json:"credentialVersion"`
	Issuer            string `json:"issuer"`
	IssuedAt          int64  `json:"issuedAt"`
	ExpirationTime    int64  `json:"expirationTime"`
	DCC               *DCC   `json:"dcc"`
}

func SerializeAndHashForSignature(unprotectedHeader CWTHeader, protectedHeaderCbor, payloadCbor []byte) (hash []byte, err error) {
	// Serialize and hash the CWT, or use empty byte string value if empty
	unprotectedHeaderCbor := make([]byte, 0)
	if unprotectedHeader != (CWTHeader{}) {
		unprotectedHeaderCbor, err = cbor.Marshal(unprotectedHeader)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not CBOR marshal unprotected header", 0)
		}
	}

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

func ReadCWT(cwt *CWT) (hcert *HealthCertificate, err error) {
	// Unmarshal payload
	var payload *CWTPayload
	err = cbor.Unmarshal(cwt.Payload, &payload)
	if err != nil {
		// Try to parse the CWT with float timestamps, then put it back into the regular structure
		var altPayload *cwtPayloadWithFloatTimestamps
		altErr := cbor.Unmarshal(cwt.Payload, &altPayload)
		if altErr != nil {
			// Use the original error, as it is more likely to be of use
			return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal CWT payload", 0)
		}

		payload = &CWTPayload{
			Issuer:         altPayload.Issuer,
			ExpirationTime: int64(altPayload.ExpirationTime),
			IssuedAt:       int64(altPayload.IssuedAt),
			HCert:          altPayload.HCert,
		}
	}

	if payload.HCert == nil || payload.HCert.DCC == nil {
		return nil, errors.Errorf("Could not process empty hcert or dcc structure")
	}

	// Read DCC itself
	dcc, err := ReadDCC(payload.HCert.DCC)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not read DCC", 0)
	}

	// Insert CWT fields into top level structure
	return &HealthCertificate{
		CredentialVersion: 1,
		Issuer:            payload.Issuer,
		IssuedAt:          payload.IssuedAt,
		ExpirationTime:    payload.ExpirationTime,

		// Fix up inner map[interface{}]interface{} fields so value can be JSON serialized
		DCC: dcc,
	}, nil
}
