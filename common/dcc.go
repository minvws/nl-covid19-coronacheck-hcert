package common

type DCC struct {

}

func ReadDCC(dccCbor []byte) (dcc *DCC, err error) {
	return &DCC{}, nil
}