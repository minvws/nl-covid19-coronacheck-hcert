package common

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/base45-go/eubase45"
	"io/ioutil"
)

const (
	COSE_SIGN1_TAG     = 18
	CURRENT_CONTEXT_ID = '1'
)

func MarshalQREncoded(signedCWT *CWT) ([]byte, error) {
	// CBOR marshal
	proofCbor, err := cbor.Marshal(cbor.Tag{
		Number:  COSE_SIGN1_TAG,
		Content: signedCWT,
	})
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR serialize CWT", 0)
	}

	// Zlib compress
	var proofCompressed bytes.Buffer
	zw, err := zlib.NewWriterLevel(&proofCompressed, flate.BestCompression)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not create zlib writer", 0)
	}

	_, err = zw.Write(proofCbor)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not write to zlib writer", 0)
	}

	err = zw.Close()
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not close zlib writer", 0)
	}

	// EUBase45 encode proof
	proofEUBase45 := eubase45.EUBase45Encode(proofCompressed.Bytes())

	// Prefix
	prefix := append([]byte{'H', 'C'}, CURRENT_CONTEXT_ID, ':')
	prefixedProof := append(prefix, proofEUBase45...)

	return prefixedProof, nil
}

func UnmarshalQREncoded(proofPrefixed []byte) (cwt *CWT, err error) {
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
		return nil, errors.WrapPrefix(err, "Could not decompress QR", 0)
	}

	// Unmarshal CWT
	err = cbor.Unmarshal(proofCbor, &cwt)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal QR as CWT", 0)
	}

	return cwt, nil
}

func HasEUPrefix(bts []byte) bool {
	_, _, err := extractContextId(bts)
	return err == nil
}

func extractContextId(proofPrefixed []byte) (contextId byte, proofEUBase45 []byte, err error) {
	if len(proofPrefixed) < 4 {
		return 0x00, nil, errors.Errorf("Could not process abnormally short QR")
	}

	if proofPrefixed[0] != 'H' || proofPrefixed[1] != 'C' || proofPrefixed[3] != ':' {
		return 0x00, nil, errors.Errorf("QR is not prefixed as a EU Health Credential")
	}

	contextId = proofPrefixed[2]
	if !((contextId >= '0' && contextId <= '9') || (contextId >= 'A' && contextId <= 'Z')) {
		return 0x00, nil, errors.Errorf("QR has invalid context id byte")
	}

	return contextId, proofPrefixed[4:], nil
}
