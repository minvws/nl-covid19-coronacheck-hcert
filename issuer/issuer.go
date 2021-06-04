package issuer

import (
	"crypto/sha256"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
)

const (
	COSE_SIGN1_CONTEXT = "Signature1"
)

type Signer interface {
	GetKID(keyUsage string) (kid []byte, err error)
	Sign(hash []byte) (signature []byte, err error)
}

type Issuer struct {
	signer Signer
}

type IssueSpecification struct {
	KeyUsage string

	Issuer         string
	IssuedAt       int64
	ExpirationTime int64

	DCC map[string]interface{}
}

func New(signer Signer) *Issuer {
	return &Issuer{
		signer: signer,
	}
}

func (iss *Issuer) IssueQREncoded(spec *IssueSpecification) ([]byte, error) {
	signed, err := iss.Issue(spec)
	if err != nil {
		return nil, err
	}

	signedQREncoded, err := common.MarshalQREncoded(signed)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not QR encode credential", 0)
	}

	return signedQREncoded, nil
}

// Issue intentionally doesn't support all the different COSE bells and whistles, and only does
// one thing well: serialize electronic health certificates for ECDSA / SHA-256 signing
func (iss *Issuer) Issue(spec *IssueSpecification) (signed *common.CWT, err error) {
	kid, err := iss.signer.GetKID(spec.KeyUsage)
	if err != nil {
		return nil, err
	}

	unsigned, hash, err := serialize(kid, spec)
	if err != nil {
		return nil, err
	}

	signature, err := iss.signer.Sign(hash)
	if err != nil {
		return nil, err
	}

	signed = &common.CWT{
		Protected: unsigned.Protected,
		Payload:   unsigned.Payload,
		Signature: signature,
	}

	return signed, nil
}

func serialize(kid []byte, spec *IssueSpecification) (unsigned *common.CWT, hash []byte, err error) {
	// Build and serialize the protected protectedHeader
	protectedHeader := &common.CWTHeader{
		Alg: common.ALG_ES256,
		KID: kid,
	}

	protectedHeaderCbor, err := cbor.Marshal(protectedHeader)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR marshal CWT protectedHeader", 0)
	}

	// Use an empty unprotected header
	unprotectedHeaderCbor := make([]byte, 0)

	// Serialize DCC separately, and then the rest of the payload
	dgcCbor, err := cbor.Marshal(spec.DCC)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR marshal DCC", 0)
	}

	payload := &common.CWTPayload{
		Issuer:         spec.Issuer,
		ExpirationTime: spec.ExpirationTime,
		IssuedAt:       spec.IssuedAt,
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
		protectedHeaderCbor,
		unprotectedHeaderCbor,
		payloadCbor,
	}

	serializedForSigning, err := cbor.Marshal(toSign)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR serialize for signing", 0)
	}

	hashArr := sha256.Sum256(serializedForSigning)
	hash = hashArr[:]

	// Build the yet unsigned CWT
	unsigned = &common.CWT{
		Protected: protectedHeaderCbor,
		Payload:   payloadCbor,
	}

	return unsigned, hash, nil
}
