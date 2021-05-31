package holder

import (
	"encoding/json"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
)

func ReadQREncoded(proofPrefixed []byte) (dgcJson []byte, err error) {
	cwt, err := common.UnmarshalQREncoded(proofPrefixed)
	if err != nil {
		return nil, err
	}

	return Read(cwt)
}

func Read(cwt *common.CWT) (hcertJson []byte, err error) {
	payload, err := common.UnmarshalCWTPayload(cwt.Payload)
	if err != nil {
		return nil, err
	}

	if payload.HCert == nil || payload.HCert.DGCv1 == nil {
		return nil, errors.Errorf("Could not process empty hcert or dgcv1 structure")
	}

	// Reserialize DCC as JSON
	var rawDCC map[interface{}]interface{}
	err = cbor.Unmarshal(payload.HCert.DGCv1, &rawDCC)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal dgcv1 structure", 0)
	}

	// Fix up inner map[interface{}]interface{} fields so value can be JSON serialized
	dcc := fixMap(rawDCC)

	// Insert CWT fields into top level structure
	hcert := map[string]interface{}{
		"issuer":         payload.Issuer,
		"issuedAt":       payload.IssuedAt,
		"expirationTime": payload.ExpirationTime,
		"dcc":            dcc,
	}

	hcertJson, err = json.Marshal(hcert)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not JSON marshal DCC intermediate", 0)
	}

	return hcertJson, nil
}

func fixMap(val map[interface{}]interface{}) map[string]interface{} {
	res := map[string]interface{}{}
	for k, v := range val {
		switch tk := k.(type) {
		case string:
			switch tv := v.(type) {
			case map[interface{}]interface{}:
				res[tk] = fixMap(tv)
			case []interface{}:
				res[tk] = fixSlice(tv)
			default:
				res[tk] = v
			}
		}
	}

	return res
}

func fixSlice(val []interface{}) []interface{} {
	var res []interface{}
	for _, v := range val {
		switch tv := v.(type) {
		case map[interface{}]interface{}:
			res = append(res, fixMap(tv))
		case []interface{}:
			res = append(res, fixSlice(tv))
		default:
			res = append(res, v)
		}
	}

	return res
}
