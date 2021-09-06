package verifier

import (
	"crypto/x509"
	"encoding/base64"
	"github.com/go-errors/errors"
)

type PksLookup map[string][]*AnnotatedEuropeanPk

type AnnotatedEuropeanPk struct {
	SubjectPk      []byte   `json:"subjectPk"`
	KeyUsage       []string `json:"keyUsage"`
	SubjectAltName string   `json:"san"`
	IssuerAltName  string   `json:"ian"`

	// LoadedPK is either of type *ecdsa.PublicKey or *rsa.PublicKey
	LoadedPk interface{} `json:"-"`
}

func (epks PksLookup) findIssuerPk(kid []byte) ([]*AnnotatedEuropeanPk, error) {
	// Check if key id is present
	kidB64 := base64.StdEncoding.EncodeToString(kid)
	annotatedPks, ok := epks[kidB64]
	if !ok {
		return nil, errors.Errorf("Could not find European public key for this key id")
	}

	// Collect all (cached) public keys
	pks := make([]*AnnotatedEuropeanPk, 0, len(annotatedPks))
	for _, annotatedPk := range annotatedPks {
		if annotatedPk.LoadedPk == nil {
			// Allow parsing errors at this stage, so that kid collisions
			//  cannot prevent another key from verifying
			var err error
			annotatedPk.LoadedPk, err = x509.ParsePKIXPublicKey(annotatedPk.SubjectPk)
			if err != nil {
				continue
			}
		}

		pks = append(pks, annotatedPk)
	}

	if len(pks) == 0 {
		return nil, errors.Errorf("Could not find any valid European public keys for this key id")
	}

	return pks, nil
}
