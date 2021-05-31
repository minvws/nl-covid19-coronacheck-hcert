package main

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/holder"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/localsigner"
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

		DCC: map[string]interface{}{"foo": "bar"},
	})
	if err != nil {
		t.Fatal("Could not issue QR encoded:", err.Error())
	}

	// Read
	foo, err := holder.ReadQREncoded(qr)
	if err != nil {
		fmt.Println(err.(*errors.Error).ErrorStack())
		t.Fatal("Could not read back QR encoded credential:", err.Error())
	}

	fmt.Println(string(foo))
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
