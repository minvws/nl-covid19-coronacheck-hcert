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
	findIssuerPk common.FindIssuerPkFunc
}

func New(findIssuerPk common.FindIssuerPkFunc) *Verifier {
	return &Verifier{
		findIssuerPk: findIssuerPk,
	}
}

func (v *Verifier) VerifyQREncoded(proofPrefixed []byte) (hcert *common.HealthCertificate, err error) {
	cwt, err := common.UnmarshalQREncoded(proofPrefixed)
	if err != nil {
		return nil, err
	}

	return v.Verify(cwt)
}

func (v *Verifier) Verify(cwt *common.CWT) (hcert *common.HealthCertificate, err error) {
	// Unmarshal protected header
	var protectedHeader *common.CWTHeader
	err = cbor.Unmarshal(cwt.Protected, &protectedHeader)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal protected header for verification", 0)
	}

	if protectedHeader == nil {
		return nil, errors.Errorf("No protected header is present in CWT")
	}

	// Try to find the KID and public key(s)
	kid, err := findKID(protectedHeader, &cwt.Unprotected)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Couldn't find CWT KID", 0)
	}

	pks, err := v.findIssuerPk(kid)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not find key for verification", 0)
	}

	// Calculate the CWT hash
	hash, err := common.SerializeAndHashForSignature(cwt.Unprotected, cwt.Protected, cwt.Payload)
	if err != nil {
		return nil, err
	}

	// Try to verify with all public keys; which in practice is one key
	err = verifySignature(protectedHeader.Alg, pks, hash, cwt.Signature)
	if err != nil {
		return nil, err
	}

	// Unmarshal verified payload and metadata
	return common.ReadCWT(cwt)
}

func findKID(protectedHeader *common.CWTHeader, unprotectedHeader *common.CWTHeader) (kid []byte, err error) {
	// Determine kid from protected and unprotected header
	if protectedHeader.KID != nil {
		kid = *protectedHeader.KID
	} else if unprotectedHeader.KID != nil {
		kid = *unprotectedHeader.KID
	}

	if kid == nil {
		return nil, errors.Errorf("Could not find key identifier in protected or unprotected header")
	}

	return kid, nil
}

func verifySignature(alg int, pks []interface{}, hash, signature []byte) (err error) {
	if len(pks) == 0 {
		return errors.Errorf("No public keys to verify with")
	}

	for _, pk := range pks {
		// Default error
		err = errors.Errorf("Encountered invalid public key type in trusted key store")

		switch pk := pk.(type) {
		case *ecdsa.PublicKey:
			err = verifyECDSASignature(alg, pk, hash, signature)

		case *rsa.PublicKey:
			err = verifyRSASignature(alg, pk, hash, signature)
		}

		// Check for successful validation
		if err == nil {
			return nil
		}
	}

	// Return last verification error
	return errors.WrapPrefix(err, "Could not verify signature", 0)
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
