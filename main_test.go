package main

import (
	"bytes"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"github.com/minvws/nl-covid19-coronacheck-hcert/holder"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer"
	issuercommon "github.com/minvws/nl-covid19-coronacheck-hcert/issuer/common"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/localsigner"
	"github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	"testing"
	"time"
)

var certFile = "./testdata/cert.pem"
var keyFile = "./testdata/key.pem"

func TestIssueHoldVerify(t *testing.T) {
	// Create local signer and issuer
	lsc := &localsigner.Configuration{
		KeyDescriptions: []*localsigner.KeyDescription{
			{
				KeyUsage:        "vaccination",
				CertificatePath: certFile,
				KeyPath:         keyFile,
			},
		},
	}

	ls, err := localsigner.New(lsc)
	if err != nil {
		t.Fatal("Could not create local signer:", err.Error())
	}

	iss := issuer.New(ls)

	// Issue
	qr, err := iss.IssueQREncoded(&issuer.IssueSpecification{
		KeyUsage: "vaccination",

		Issuer:         "NL",
		IssuedAt:       time.Now().UTC().Unix(),
		ExpirationTime: time.Now().AddDate(0, 0, 28).UTC().Unix(),

		DCC: &common.DCC{
			Version:     "1.0.0",
			DateOfBirth: "01-01-1970",
			Name: &common.DCCName{
				StandardizedFamilyName: "WAT",
			},
		},
	})
	if err != nil {
		t.Fatal("Could not issue QR encoded:", err.Error())
	}

	// Read
	h := holder.New()

	_, err = h.ReadQREncoded(qr)
	if err != nil {
		fmt.Println(err.(*errors.Error).ErrorStack())
		t.Fatal("Could not read back QR encoded credential:", err.Error())
	}

	// Verify
	findIssuerPk := func(targetKid []byte) ([]interface{}, error) {
		cert, kid, err := issuercommon.LoadDSCCertificateFile(certFile)
		if err != nil {
			t.Fatal("Could not read certificate file:", err.Error())
		}

		if !bytes.Equal(targetKid, kid) {
			t.Fatal("Incorrect KID encountered during verification")
		}

		return []interface{}{cert.PublicKey}, nil
	}

	v := verifier.New(findIssuerPk)
	_, err = v.VerifyQREncoded(qr)
	if err != nil {
		t.Fatal("Could not verify proof that was just issued:", err.Error())
	}
}
