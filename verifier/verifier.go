package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"math/big"
)

type Verifier struct {
	pksLookup PksLookup
}

func New(pksLookup PksLookup) *Verifier {
	return &Verifier{
		pksLookup: pksLookup,
	}
}

func (v *Verifier) VerifyQREncoded(proofPrefixed []byte) (hcert *common.HealthCertificate, pk *AnnotatedEuropeanPk, err error) {
	cwt, err := common.UnmarshalQREncoded(proofPrefixed)
	if err != nil {
		return nil, nil, err
	}

	return v.Verify(cwt)
}

func (v *Verifier) Verify(cwt *common.CWT) (hcert *common.HealthCertificate, pk *AnnotatedEuropeanPk, err error) {
	// Unmarshal protected header
	var protectedHeader *common.CWTHeader
	err = cbor.Unmarshal(cwt.Protected, &protectedHeader)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not CBOR unmarshal protected header for verification", 0)
	}

	if protectedHeader == nil {
		return nil, nil, errors.Errorf("No protected header is present in CWT")
	}

	// Try to find the KID and public key(s)
	kid, err := findKID(protectedHeader, &cwt.Unprotected)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Couldn't find CWT KID", 0)
	}

	pks, err := v.pksLookup.findIssuerPk(kid)
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "Could not find key for verification", 0)
	}

	// Calculate the CWT hash
	hash, err := common.SerializeAndHashForSignature(cwt.Protected, cwt.Payload)
	if err != nil {
		return nil, nil, err
	}

	// Try to verify with all public keys; which in practice is one key
	pk, err = verifySignature(protectedHeader.Alg, pks, hash, cwt.Signature)
	if err != nil {
		return nil, nil, err
	}

	// Unmarshal verified payload and metadata
	hcert, err = common.ReadCWT(cwt)
	if err != nil {
		return nil, nil, err
	}

	return hcert, pk, nil
}

func findKID(protectedHeader *common.CWTHeader, unprotectedHeader *common.CWTHeader) (kid []byte, err error) {
	// Determine kid from protected and unprotected header
	if protectedHeader.KID != nil {
		kid = protectedHeader.KID
	} else if unprotectedHeader.KID != nil {
		kid = unprotectedHeader.KID
	} else {
		return nil, errors.Errorf("Could not find key identifier in protected or unprotected header")
	}

	return kid, nil
}

func verifySignature(alg int, pks []*AnnotatedEuropeanPk, hash, signature []byte) (*AnnotatedEuropeanPk, error) {
	if len(pks) == 0 {
		return nil, errors.Errorf("No public keys to verify with")
	}

	var err error
	for _, pk := range pks {
		// Default error
		err = errors.Errorf("Encountered invalid public key type in trusted key store")

		switch pk := pk.LoadedPk.(type) {
		case *ecdsa.PublicKey:
			err = verifyECDSASignature(alg, pk, hash, signature)

		case *rsa.PublicKey:
			err = verifyRSASignature(alg, pk, hash, signature)
		}

		// Check for successful validation
		if err == nil {
			return pk, nil
		}
	}

	// Return last verification error
	return nil, errors.WrapPrefix(err, "Could not verify signature", 0)
}

func verifyECDSASignature(alg int, pk *ecdsa.PublicKey, hash, signature []byte) error {
	if alg != common.ALG_ES256 {
		return errors.Errorf("Incorrect algorithm type for ECDSA public key")
	}

	keyByteSize := pk.Curve.Params().BitSize / 8
	if len(signature) != keyByteSize*2 {
		return errors.Errorf("Signature has an incorrect length")
	}

	r := new(big.Int).SetBytes(signature[:keyByteSize])
	s := new(big.Int).SetBytes(signature[keyByteSize:])

	ok := ecdsa.Verify(pk, hash, r, s)
	if !ok {
		return errors.Errorf("Signature does not verify against ECDSA public key")
	}

	return nil
}

func verifyRSASignature(alg int, pk *rsa.PublicKey, hash, signature []byte) error {
	if alg != common.ALG_PS256 {
		return errors.Errorf("CWT has incorrect algorithm type for RSA public key")
	}

	err := rsa.VerifyPSS(pk, crypto.SHA256, hash, signature, nil)
	if err != nil {
		return errors.Errorf("CWT signature does not verify against RSA public key")
	}

	return nil
}
