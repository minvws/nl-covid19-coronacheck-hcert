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
	cwt, contextId, err := common.UnmarshalQREncoded(proofPrefixed)
	if err != nil {
		return nil, err
	}

	err = v.Verify(cwt)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not verify proof", 0)
	}

	return common.ReadCWT(cwt, contextId)
}

func (v *Verifier) Verify(cwt *common.CWT) (err error) {
	// Unmarshal protected header
	var protectedHeader *common.CWTHeader
	err = cbor.Unmarshal(cwt.Protected, &protectedHeader)
	if err != nil {
		return errors.WrapPrefix(err, "Could not CBOR unmarshal protected header for verification", 0)
	}

	if protectedHeader == nil {
		return errors.Errorf("No protected header is present in CWT")
	}

	// Try to find the KID and public key(s)
	kid, err := findKID(protectedHeader, &cwt.Unprotected)
	if err != nil {
		return errors.WrapPrefix(err, "Couldn't find CWT KID", 0)
	}

	pks, err := v.findIssuerPk(kid)
	if err != nil {
		return errors.WrapPrefix(err, "Could not find key identifier for verification", 0)
	}

	// Serialize and hash the CWT, or use empty bstr if not present
	unprotectedHeaderCbor := make([]byte, 0)
	if cwt.Unprotected != (common.CWTHeader{}) {
		unprotectedHeaderCbor, err = cbor.Marshal(cwt.Unprotected)
		if err != nil {
			return errors.WrapPrefix(err, "Could not CBOR marshal unprotected header for verification", 0)
		}
	}

	// Calculate the CWT hash
	hash, err := common.SerializeAndHashForSignature(cwt.Protected, unprotectedHeaderCbor, cwt.Payload)
	if err != nil {
		return err
	}

	// Try to verify with all public keys; which in practice is one key
	for _, pk := range pks {
		// Default error
		err = errors.Errorf("Encountered invalid public key type in trusted key store")

		switch pk := pk.(type) {
		case *ecdsa.PublicKey:
			err = verifyECDSASignature(protectedHeader.Alg, pk, hash, cwt.Signature)

		case *rsa.PublicKey:
			err = verifyRSASignature(protectedHeader.Alg, pk, hash, cwt.Signature)
		}

		// Check for successful validation
		if err == nil {
			return nil
		}
	}

	return errors.WrapPrefix(err, "Could not verify signature", 0)
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
