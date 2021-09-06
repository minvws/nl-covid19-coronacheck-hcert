package server

import (
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"github.com/minvws/nl-covid19-coronacheck-hcert/verifier"
	"net/http"
	"os"
)

type Configuration struct {
	ListenAddress string
	ListenPort    string

	PublicKeysPath string
}

type server struct {
	config   *Configuration
	verifier *verifier.Verifier
}

type verificationRequest struct {
	Credential string `json:"credential"`
}

type verificationResponse struct {
	ValidSignature    bool                      `json:"validSignature"`
	VerificationError string                    `json:"verificationError"`
	HealthCertificate *common.HealthCertificate `json:"healthCertificate"`
}

func Run(config *Configuration) error {
	pksJson, err := os.ReadFile(config.PublicKeysPath)
	if err != nil {
		return errors.WrapPrefix(err, "Could not read verifier config file", 0)
	}

	var epks verifier.PksLookup
	err = json.Unmarshal(pksJson, &epks)
	if err != nil {
		return errors.WrapPrefix(err, "Could not JSON unmarshal verifier config", 0)
	}

	verif := verifier.New(epks)

	// Serve
	s := &server{
		config:   config,
		verifier: verif,
	}

	err = s.Serve()
	if err != nil {
		return errors.WrapPrefix(err, "Could not start server", 0)
	}

	return nil
}

func (s *server) Serve() error {
	addr := fmt.Sprintf("%s:%s", s.config.ListenAddress, s.config.ListenPort)
	fmt.Printf("Starting verification server, listening at %s\n", addr)

	handler := s.buildHandler()
	err := http.ListenAndServe(addr, handler)
	if err != nil {
		return errors.WrapPrefix(err, "Could not start listening", 0)
	}

	return nil
}

func (s *server) buildHandler() *http.ServeMux {
	handler := http.NewServeMux()
	handler.HandleFunc("/verify_signature", s.handleVerifySignature)

	return handler
}

func (s *server) handleVerifySignature(w http.ResponseWriter, r *http.Request) {
	req := &verificationRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not JSON unmarshal verification request", 0))
		return
	}

	var response *verificationResponse
	hcert, err := s.verifier.VerifyQREncoded([]byte(req.Credential))
	if err != nil {
		response = &verificationResponse{
			ValidSignature:    false,
			VerificationError: err.Error(),
		}
	} else {
		response = &verificationResponse{
			ValidSignature:    true,
			HealthCertificate: hcert,
		}
	}

	responseJson, err := json.Marshal(response)
	if err != nil {
		writeError(w, errors.WrapPrefix(err, "Could not JSON marshal verification response", 0))
		return
	}

	w.WriteHeader(200)
	_, _ = w.Write(responseJson)
}

func writeError(w http.ResponseWriter, err error) {
	fmt.Println(err.Error())
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
