package common

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"strconv"
)

type HealthCertificate struct {
	CredentialVersion int                    `json:"credentialVersion"`
	Issuer            string                 `json:"issuer"`
	IssuedAt          int64                  `json:"issuedAt"`
	ExpirationTime    int64                  `json:"expirationTime"`
	DCC               map[string]interface{} `json:"dcc"`
}

func ReadCWT(cwt *CWT, contextId byte) (hcert *HealthCertificate, err error) {
	payload, err := UnmarshalCWTPayload(cwt.Payload)
	if err != nil {
		return nil, err
	}

	if payload.HCert == nil || payload.HCert.DCC == nil {
		return nil, errors.Errorf("Could not process empty hcert or dgcv1 structure")
	}

	// Reserialize DCC as JSON
	var rawDCC map[interface{}]interface{}
	err = cbor.Unmarshal(payload.HCert.DCC, &rawDCC)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal dgcv1 structure", 0)
	}

	// Insert CWT fields into top level structure
	credentialVersion, _ := strconv.ParseInt(string(contextId), 16, 0)
	return &HealthCertificate{
		CredentialVersion: int(credentialVersion),
		Issuer:            payload.Issuer,
		IssuedAt:          payload.IssuedAt,
		ExpirationTime:    payload.ExpirationTime,

		// Fix up inner map[interface{}]interface{} fields so value can be JSON serialized
		DCC: fixMap(rawDCC),
	}, nil
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
