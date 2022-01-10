package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"github.com/minvws/nl-covid19-coronacheck-hcert/holder"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer"
	issuercommon "github.com/minvws/nl-covid19-coronacheck-hcert/issuer/common"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/localsigner"
	"github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	"math/big"
	"reflect"
	"testing"
	"time"
)

var certFile = "./testdata/cert.pem"
var keyFile = "./testdata/key.pem"

func TestIssueHoldVerify(t *testing.T) {
	// Create local signer and issuer
	lsc := &localsigner.Configuration{
		UsageKeys: map[string]*localsigner.Key{
			"vaccination": {
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
	qr, proofIdentifier, err := iss.IssueQREncoded(&issuer.IssueSpecification{
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
	pksLookup := createPksLookup(t)
	v := verifier.New(pksLookup)

	verified, err := v.VerifyQREncoded(qr)
	if err != nil {
		t.Fatal("Could not verify proof that was just issued:", err.Error())
	}

	if !reflect.DeepEqual(proofIdentifier, verified.ProofIdentifier) {
		t.Fatal("Issued proof identifier did not match verified proof identifier")
	}

	for _, lookupPk := range pksLookup {
		if verified.PublicKey != lookupPk[0] {
			t.Fatal("Returned public key does not matching testing key")
		}
	}
}

func TestSignatureCanonicalization(t *testing.T) {
	// Test some pregenerated signature components
	rBytes, _ := base64.StdEncoding.DecodeString("mvR6wvbbKv8iEgKP1K6QOd4qs8NG4g5bU3EZx8veWLM=")
	highSBytes, _ := base64.StdEncoding.DecodeString("mFMXaeGX+Unt2GURs6L2Mos0X3+JY0ShkLU1NMvldvY=")
	canonicalSigB64 := "mvR6wvbbKv8iEgKP1K6QOd4qs8NG4g5bU3EZx8veWLNnrOiVHmgGtxInmu5MXQnNMbKbLh20WeNjBJWOMH2uWw=="

	r := new(big.Int).SetBytes(rBytes)
	highS := new(big.Int).SetBytes(highSBytes)

	sigBytes := common.CanonicalSignatureBytes(r, highS, elliptic.P256().Params())
	if base64.StdEncoding.EncodeToString(sigBytes) != canonicalSigB64 {
		t.Fatal("Incorrect canonicalization of ECDSA P-256 s component")
	}

	// Test that verifying a high-s QR returns the correct proof identifier based on low-s
	highSQR := []byte(`HC1:NCFO30620FFWTWGVLKG997LLJTQ*NQ2ZOX*4C7B0XKBJCKR93F368RF$63F36NML%6Y50.FKMTKO/EZKEZ96446C56GVC*JC7463W5Y961A6//6TPCBEC7ZKW.CF8CW.C5WEH1B2UAI3DF8CI3D2WE27BN/P+L2148BUU30R4S7K6SXP3FAJUMAV.Q3 48ZQRV44A0L7MOVPLHL COH9B2024QAA+F/9TIZF+OF6SM.0RSH6$K4R1J%SOV50U504EW%S9K1`)

	pksLookup := createPksLookup(t)
	v := verifier.New(pksLookup)

	verified, err := v.VerifyQREncoded(highSQR)
	if err != nil {
		t.Fatal("Could not verify QR with high S")
	}

	if base64.StdEncoding.EncodeToString(verified.ProofIdentifier) != "FnDyemxSgralp3zx1VO20g==" {
		t.Fatal("QR-code with high S component did not return the correct proof identifier")
	}
}

func createPksLookup(t *testing.T) verifier.PksLookup {
	cert, kidBytes, err := issuercommon.LoadDSCCertificateFile(certFile)
	if err != nil {
		t.Fatal("Could not read certificate file:", err.Error())
	}

	pkBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	kid := base64.StdEncoding.EncodeToString(kidBytes)

	return verifier.PksLookup{
		kid: {
			{
				SubjectPk: pkBytes,
			},
		},
	}
}
