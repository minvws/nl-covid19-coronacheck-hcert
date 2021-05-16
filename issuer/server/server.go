package server

import (
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/localsigner"
	"net/http"
	"time"
)

type Configuration struct {
	ListenAddress string
	ListenPort    string

	DSCCertificatePath string
	DSCKeyPath         string
}

type GetCredentialRequest struct {
	CertificateOID string                 `json:"oid"`
	ExpiryTime     int64                  `json:"exp"`
	DGC            map[string]interface{} `json:"dgc"`
}

type GetCredentialResponse struct {
	SignedCWT []byte `json:"signedCWT"`
}

var dsc *localsigner.DSC

func Serve(config *Configuration) error {
	var err error
	dsc, err = localsigner.LoadDSC(config.DSCCertificatePath, config.DSCKeyPath)
	if err != nil {
		return errors.WrapPrefix(err, "Could not load DSC and private key", 0)
	}

	addr := fmt.Sprintf("%s:%s", config.ListenAddress, config.ListenPort)
	fmt.Printf("Starting server, listening at %s\n", addr)

	handler := buildHandler()
	err = http.ListenAndServe(addr, handler)
	if err != nil {
		return errors.WrapPrefix(err, "Could not start listening", 0)
	}

	return nil
}

func buildHandler() *http.ServeMux {
	handler := http.NewServeMux()
	handler.HandleFunc("/get_credential", getCredential)

	return handler
}

func getCredential(w http.ResponseWriter, r *http.Request) {
	credentialRequest := &GetCredentialRequest{}
	err := json.NewDecoder(r.Body).Decode(credentialRequest)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not decode credentialRequest", 0))
		return
	}

	if len(credentialRequest.DGC) == 0 {
		writeError(w, errors.Errorf("Refusing to sign empty DGC"))
		return
	}

	unixNow := time.Now().Unix()
	unsigned, hash, err := issuer.Serialize(&issuer.ToSerialize{
		KeyIdentifier:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		Issuer:         "NL",
		IssuedAt:       unixNow,
		ExpirationTime: unixNow + 180*24*60*60,
		DGC:            credentialRequest.DGC,
	})
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not serialize message for signing", 0))
		return
	}

	signature, err := localsigner.Sign(dsc, hash)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not sign message", 0))
		return
	}

	signedCWTCbor, err := issuer.FinalizeCWT(unsigned, signature)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not CBOR serialize signed CWT", 0))
		return
	}

	responseBody, err := json.Marshal(&GetCredentialResponse{
		SignedCWT: signedCWTCbor,
	})
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not JSON marshal credential response", 0))
		return
	}

	w.WriteHeader(200)
	_, _ = w.Write(responseBody)
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
