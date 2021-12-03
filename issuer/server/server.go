package server

import (
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/hsmsigner"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/localsigner"
	"net/http"
	"time"
)

type Configuration struct {
	ListenAddress     string
	ListenPort        string
	IssuerCountryCode string

	LocalSignerConfig *localsigner.Configuration
	HSMSignerConfig   *hsmsigner.Configuration
}

type server struct {
	config *Configuration
	issuer *issuer.Issuer
}

type GetCredentialRequest struct {
	KeyUsage       string      `json:"keyUsage"`
	ExpirationTime string      `json:"expirationTime"`
	DCC            *common.DCC `json:"dcc"`
}

type GetCredentialResponse struct {
	Credential      string `json:"credential"`
	ProofIdentifier []byte `json:"proofIdentifier"`
}

func Run(config *Configuration) error {
	// Create either a local or HSM signer
	var signer issuer.Signer
	if config.HSMSignerConfig != nil {
		var err error
		signer, err = hsmsigner.New(config.HSMSignerConfig)
		if err != nil {
			return errors.WrapPrefix(err, "Could not create HSM signer", 0)
		}
	} else {
		var err error
		signer, err = localsigner.New(config.LocalSignerConfig)
		if err != nil {
			return errors.WrapPrefix(err, "Could not create local signer", 0)
		}
	}

	iss := issuer.New(signer)

	// Serve
	s := &server{
		config: config,
		issuer: iss,
	}

	err := s.Serve()
	if err != nil {
		return errors.WrapPrefix(err, "Could not start server", 0)
	}

	return nil
}

func (s *server) Serve() error {
	addr := fmt.Sprintf("%s:%s", s.config.ListenAddress, s.config.ListenPort)
	fmt.Printf("Starting issuance server, listening at %s\n", addr)

	handler := s.buildHandler()
	err := http.ListenAndServe(addr, handler)
	if err != nil {
		return errors.WrapPrefix(err, "Could not start listening", 0)
	}

	return nil
}

func (s *server) buildHandler() *http.ServeMux {
	handler := http.NewServeMux()
	handler.HandleFunc("/get_credential", s.handleGetCredential)

	return handler
}

func (s *server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	credentialRequest := &GetCredentialRequest{}
	err := json.NewDecoder(r.Body).Decode(credentialRequest)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not JSON unmarshal credentialRequest", 0))
		return
	}

	if credentialRequest.DCC == nil {
		writeError(w, errors.Errorf("DCC was not present in request"))
		return
	}

	unixNow := time.Now().Unix()
	expirationTime, err := time.Parse(time.RFC3339, credentialRequest.ExpirationTime)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not parse expirationTime", 0))
		return
	}

	credential, proofIdentifier, err := s.issuer.IssueQREncoded(&issuer.IssueSpecification{
		KeyUsage:       credentialRequest.KeyUsage,
		Issuer:         s.config.IssuerCountryCode,
		IssuedAt:       unixNow,
		ExpirationTime: expirationTime.Unix(),
		DCC:            credentialRequest.DCC,
	})
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not issue credential", 0))
		return
	}

	responseJson, err := json.Marshal(&GetCredentialResponse{
		Credential:      string(credential),
		ProofIdentifier: proofIdentifier,
	})
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not JSON marshal credential response", 0))
		return
	}

	w.WriteHeader(200)
	_, _ = w.Write(responseJson)
}

func writeError(w http.ResponseWriter, err error) {
	fmt.Println(err.Error())
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
