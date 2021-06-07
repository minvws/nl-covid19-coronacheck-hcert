package holder

import (
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
)

type Holder struct {
}

func New() *Holder {
	return &Holder{}
}

func (h *Holder) ReadQREncoded(proofPrefixed []byte) (hcert *common.HealthCertificate, err error) {
	cwt, err := common.UnmarshalQREncoded(proofPrefixed)
	if err != nil {
		return nil, err
	}

	return common.ReadCWT(cwt)
}
