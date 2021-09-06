package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"github.com/minvws/nl-covid19-coronacheck-hcert/holder"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/localsigner"
	"github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	"testing"
	"time"
)

func TestSmoke(t *testing.T) {
	// Create local signer and issuer
	ls, err := localsigner.New(certificatePem, keyPem)
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
	pksLookup := createPksLookup()
	v := verifier.New(pksLookup)
	_, pk, err := v.VerifyQREncoded(qr)
	if err != nil {
		t.Fatal("Could not verify proof that was just issued:", err.Error())
	}

	for _, lookupPk := range pksLookup {
		if pk != lookupPk[0] {
			t.Fatal("Returned public key does not matching testing key")
		}
	}
}

func createPksLookup() verifier.PksLookup {
	pemCertBlock, _ := pem.Decode(certificatePem)
	cert, _ := x509.ParseCertificate(pemCertBlock.Bytes)
	pkBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)

	certSum := sha256.Sum256(pemCertBlock.Bytes)
	kid := base64.StdEncoding.EncodeToString(certSum[0:8])

	return verifier.PksLookup{
		kid: {
			{
				SubjectPk: pkBytes,
			},
		},
	}
}

var certificatePem = []byte(`
-----BEGIN CERTIFICATE-----
MIIBWjCCAQACEQCy6FwHOnp8fUZhXV3ThVfZMAkGByqGSM49BAEwMjEjMCEGA1UE
AwwaTmF0aW9uYWwgQ1NDQSBvZiBGcmllc2xhbmQxCzAJBgNVBAYTAkZSMB4XDTIx
MDUxODEwMjI1M1oXDTI2MDQwMjEwMjI1M1owMTEiMCAGA1UEAwwZRFNDIG51bWJl
ciAxIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATpwuZ7bn9Y/uFSO0ZRpaMgDLqLhjxIugpCmqLuHjshzUfuvB1tsCcL
eSSMFk7KUhlBXeGJqLbMAD8GHhZQVshxMAkGByqGSM49BAEDSQAwRgIhAN8zdG+4
gCzTe1yXb9CGnWkIMdJ9CiP2bOq4e9dlnfUlAiEAnSsNcNEoh50C+LvdWmEu9IFn
No/Vjg9ZQnfc+aGQmo8=
-----END CERTIFICATE-----
`)

// This private key is only included for testing purposes
var keyPem = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPYIAeQvSV7gCxjzlQTBE63jQPxsEZfNNOjrcoP7c0qJoAoGCCqGSM49
AwEHoUQDQgAE6cLme25/WP7hUjtGUaWjIAy6i4Y8SLoKQpqi7h47Ic1H7rwdbbAn
C3kkjBZOylIZQV3hiai2zAA/Bh4WUFbIcQ==
-----END EC PRIVATE KEY-----
`)
