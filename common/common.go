package common

const (
	COSE_SIGN1_CONTEXT = "Signature1"
	ALG_ES256          = -7
	ALG_PS256          = -37
)

// FindIssuerPkFunc must return a pk of type *ecdsa.PublicKey or *rsa.PublicKey
// Due to potential (intentional) kid collisions, more than one public key can be returned
type FindIssuerPkFunc func(kid []byte) (pk []interface{}, err error)

