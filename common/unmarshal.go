package common

import (
	"bytes"
	"compress/zlib"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/base45-go/eubase45"
	"io/ioutil"
)

func UnmarshalQREncoded(proofPrefixed []byte) (*CWT, error) {
	// Extract context identifier
	contextId, proofEUBase45, err := extractContextId(proofPrefixed)
	if err != nil {
		return nil, err
	}

	if contextId != '1' {
		return nil, errors.Errorf("Unrecognized QR context identifier")
	}

	// EUBase45 decode proof
	proofCompressed, err := eubase45.EUBase45Decode(proofEUBase45)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not EUBase45 decode QR", 0)
	}

	// Deflate proof
	br := bytes.NewReader(proofCompressed)
	zr, err := zlib.NewReader(br)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create zlib reader", 0)
	}

	proofCbor, err := ioutil.ReadAll(zr)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not deflate QR", 0)
	}

	// Unmarshal CWT
	var cwt *CWT
	err = cbor.Unmarshal(proofCbor, &cwt)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal QR as CWT", 0)
	}

	return cwt, nil
}

func UnmarshalCWTPayload(payloadCbor []byte) (*CWTPayload, error) {
	var payload *CWTPayload
	err := cbor.Unmarshal(payloadCbor, payload)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal CWT payload", 0)
	}

	return payload, nil
}

func extractContextId(proofPrefixed []byte) (contextId byte, proofEUBase45 []byte, err error) {
	if len(proofPrefixed) < 4 {
		return 0x00, nil, errors.Errorf("Could not process abnormally short QR")
	}

	if proofPrefixed[0] != 'H' || proofPrefixed[1] != 'C' || proofPrefixed[3] == ':' {
		return 0x00, nil, errors.Errorf("QR is not prefixed as a EU Health Credential")
	}

	return proofPrefixed[2], proofPrefixed[4:], nil
}