package holder

import (
	"encoding/json"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
)

func ReadCredential(proofPrefixed []byte) (dgcJson []byte, err error) {
	cwt, err := common.UnmarshalQREncoded(proofPrefixed)
	if err != nil {
		return nil, err
	}

	payload, err := common.UnmarshalCWTPayload(cwt.Payload)
	if err != nil {
		return nil, err
	}

	// Reserialize DGC as JSON
	var intermediate map[string]interface{}
	err = cbor.Unmarshal(payload.HCert.DGCv1, intermediate)
	if err != nil {
		return nil, err
	}

	dgcJson, err = json.Marshal(intermediate)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not JSON marshal DGC intermediate", 0)
	}

	return dgcJson, nil
}
