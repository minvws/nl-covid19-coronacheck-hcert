package issuer

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
)

type Signer interface {
	GetKID(keyUsage string) (kid []byte, err error)
	Sign(keyUsage string, hash []byte) (signature []byte, err error)
}

type Issuer struct {
	signer Signer
}

type IssueSpecification struct {
	KeyUsage string

	Issuer         string
	IssuedAt       int64
	ExpirationTime int64

	DCC *common.DCC
}

func New(signer Signer) *Issuer {
	return &Issuer{
		signer: signer,
	}
}

func (iss *Issuer) IssueQREncoded(spec *IssueSpecification) (qr, proofIdentifier []byte, err error) {
	signed, err := iss.Issue(spec)
	if err != nil {
		return nil, nil, err
	}

	signedQREncoded, err := common.MarshalQREncoded(signed)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not QR encode credential", 0)
	}

	proofIdentifier = common.CalculateProofIdentifier(signed.Signature)

	return signedQREncoded, proofIdentifier, nil
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

	signature, err := iss.signer.Sign(spec.KeyUsage, hash)
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
	// Build and serialize the protected header
	protectedHeader := &common.CWTHeader{
		Alg: common.ALG_ES256,
		KID: kid,
	}

	protectedHeaderCbor, err := cbor.Marshal(protectedHeader)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR marshal CWT protectedHeader", 0)
	}

	// Serialize DCC separately, and then the rest of the payload
	dccCbor, err := cbor.Marshal(spec.DCC)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR marshal DCC", 0)
	}

	payload := &common.CWTPayload{
		Issuer:         spec.Issuer,
		ExpirationTime: spec.ExpirationTime,
		IssuedAt:       spec.IssuedAt,
		HCert: &common.RawHealthCertificate{
			DCC: dccCbor,
		},
	}

	payloadCbor, err := cbor.Marshal(payload)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR marshal CWT payload", 0)
	}

	// Calculate the hash over the CWT
	hash, err = common.SerializeAndHashForSignature(protectedHeaderCbor, payloadCbor)
	if err != nil {
		return nil, nil, err
	}

	// Build the yet unsigned CWT
	unsigned = &common.CWT{
		Protected: protectedHeaderCbor,
		Payload:   payloadCbor,
	}

	return unsigned, hash, nil
}
