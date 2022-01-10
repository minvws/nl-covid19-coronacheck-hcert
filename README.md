# coronacheck-hcert

## Introduction

This repository contains the components for signing and verification of European Electronic Health Certificats (HCERTs) containing Digital Covid Certificates (DCCs). 

It can be used as a library, as is done by the CoronaCheck iOS and Android app through the [`coronacheck-mobile-core` library](https://github.com/minvws/nl-covid19-coronacheck-mobile-core), or used as a webservice as is done by [`coronacheck-backend-bizrules-signing-service` project](https://github.com/minvws/nl-covid19-coronacheck-backend-bizrules-signing-service).

## Usage

Installation and usage display:

```
# go install github.com/minvws/nl-covid19-coronacheck-hcert@latest
# nl-covid19-coronacheck-hcert --help

(...)

Available Commands:
  help                Help about any command
  issuance-server
  verification-server

(...)
```

### Issuance server

The issuance server can either operate in local or HSM mode. It intentionally doesn't support all the different COSE bells and whistles, and does only one thing well: serialize the DCC and HCERT for ECDSA / SHA-256 signing.

```
# nl-covid19-coronacheck-hcert issuance-server --help
Usage:
  coronacheck-hcert issuance-server [flags]

Flags:
      --config string                           path to configuration file (JSON, TOML, YAML or INI)
      --listen-address string                   address at which to listen (default "localhost")
      --listen-port string                      port at which to listen (default "4002")
      --issuer-country-code string              the country code that is used as CWT issuer (default "NL")
      --default-local-key-usages string         Default local key usages, when no keys map has been provided through configuration (default "vaccination,test,recovery")
      --default-local-certificate-path string   Default local PEM encoded certificate path, when no keys map has been provided through configuration (default "./cert.pem")
      --default-local-key-path string           Default local PEM encoded key file, when no keys map has been provided through configuration (default "./sk.pem")
      --enable-hsm                              Enable HSM signing
      --pkcs11-module-path string               Path to PKCS11 module
      --token-label string                      Label of token to use
  -h, --help                                    help for issuance-server
```

The `/get_credential` endpoint can then be used to sign HCERTs:

```
# curl --data '{
  "keyUsage": "vaccination",
  "expirationTime":"2023-01-01T00:00:00Z",
  "dcc":{"ver":"1.3.0","dob":"1990-01-01","nam":{"fn":"Doe","fnt":"DOE","gn":"John","gnt":"JOHN"},"v":[{"tg":"840539006","vp":"1119349007","mp":"EU/1/20/1528","ma":"ORG-100030215","dn":2,"sd":2,"dt":"2021-08-02","co":"NL","is":"Ministry of Health Welfare and Sport","ci":"URN:UCI:01:NL:ABCDEFGHIJKLMNO"}]}
}' http://127.0.0.1:4002/get_credential

{"credential":"HC1:NCF 10P90T9WTWGVLK-49NJ3B0J$OCC*AX*4ABB0XKBJCKR95F3 FM6003F3IT33Q4Y50.FK8ZKO/EZKEZ967L6C56GVC*JC1A6FA73W5Y96746TPCBEC7ZKW.CWOCW3ELPCG/DWOC/0A JC0/DKI949DMPCG/DOUC11A++97:EDOL9WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46.JCP9EJY8L/5M/5546.96VF6.JCBECB1A-:8$966469L6OF6VX6FVCPD0KQEPD0LVC6JD846Y96E463W5SG6UPCBJCOT9+EDL8FHZ95/D QEALEN44:+C%69AECAWE:34: CJ.CZKE9440/D+34S9E5LEWJC0FD*V3AIA%G7ZM81G72A6J+9IG7/G8HS8 *8A69TH93T9M+927BBM4B89DW3TCSE:D93W HRST2EZ1DFACBC485S+H*EANVFBWRE8WT.8ZOC1UKAHA7*7QL64Z1OBT%TBR51Z.5BRV1CA$PJUU4V50U50QCW.HJH1"}
```

#### Configuring multiple keys

For ease during local development, the `default-local-key-usages`, `default-local-certificate-path` and `default-local-key-path` options allow to specify a single default key for the local signer.

Keys for the HSM and multiple local keys can only be configured through a config file. The root of the config file should contain either a `local-usage-keys` or `hsm-usage-keys` entry. Local keys should contain a `certificate-path` and a `key-path`. HSM keys should contain a `certificate-path`, a `key-id-hex` and `key-label`. 

See these two examples:

```
{
  "local-usage-keys": {
    "vaccination": {
      "certificate-path": "Health_DSC_valid_for_vaccinations.pem",
      "key-path": "Health_DSC_valid_for_vaccinations.key"
    }
    "recovery": {
      "certificate-path": "Health_DSC_valid_for_recovery.pem",
      "key-path": "Health_DSC_valid_for_recovery.key"
    },
    "test": {
      "certificate-path": "Health_DSC_valid_for_test.pem",
      "key-path": "Health_DSC_valid_for_test.key"
    }
  }
} 
```

```
{
  "hsm-usage-keys": {
    "vaccination": {
      "certificate-path": "Health_DSC_valid_for_vaccinations.pem",
      "key-id-hex": "01",
      "key-label": "DSC-VACCINATION"
    }
    "recovery": {
      "certificate-path": "Health_DSC_valid_for_recovery.pem",
      "key-id-hex": "02",
      "key-label": "DSC-RECOVERY"
    },
    "test": {
      "certificate-path": "Health_DSC_valid_for_test.pem",
      "key-id-hex": "0A",
      "key-label": "DSC-TEST"
    }
  }
}

```


### Verification server

```
# nl-covid19-coronacheck-hcert verification-server --help
Usage:
  coronacheck-hcert verification-server [flags]

Flags:
      --config string             path to configuration file (JSON, TOML, YAML or INI)
      --listen-address string     address at which to listen (default "localhost")
      --listen-port string        port at which to listen (default "4003")
      --public-keys-path string   path to public keys JSON file (default "./public_keys.json")
  -h, --help                      help for verification-server
```

The `--public-keys-path` option expects a file with a JSON map of KID to an array of PKIX ASN.1 DER encoded public keys. For example:

```
{
  "DhspllZjSVY=": [
    {
      "subjectPk": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmcNCX0lhlqcvJ/YHl/+TDLbIO09nTsRUr7KP23Qp3KUXAcnq3EkrTVswaJx93exNhW3VeFdILS1vI84sWbJoWw==",
      "keyUsage": [
        "v"
      ]
    }
  ]
}
```

The `/verify_signature` endpoint can then be used to verify HCERT signatures. Note that only the signature is verified; this command **does not** verify issuance or expiration time, key usage OID or if the DCC is correctly formed.

```
curl --data '{
  "credential": "HC1:NCF 10P90T9WTWGVLK-49NJ3B0J$OCC*AX*4ABB0XKBJCKR95F3 FM6003F3IT33Q4Y50.FK8ZKO/EZKEZ967L6C56GVC*JC1A6FA73W5Y96746TPCBEC7ZKW.CWOCW3ELPCG/DWOC/0A JC0/DKI949DMPCG/DOUC11A++97:EDOL9WEQDD+Q6TW6FA7C466KCN9E%961A6DL6FA7D46.JCP9EJY8L/5M/5546.96VF6.JCBECB1A-:8$966469L6OF6VX6FVCPD0KQEPD0LVC6JD846Y96E463W5SG6UPCBJCOT9+EDL8FHZ95/D QEALEN44:+C%69AECAWE:34: CJ.CZKE9440/D+34S9E5LEWJC0FD*V3AIA%G7ZM81G72A6J+9IG7/G8HS8 *8A69TH93T9M+927BBM4B89DW3TCSE:D93W HRST2EZ1DFACBC485S+H*EANVFBWRE8WT.8ZOC1UKAHA7*7QL64Z1OBT%TBR51Z.5BRV1CA$PJUU4V50U50QCW.HJH1"
}' http://127.0.0.1:4003/verify_signature

{
  "validSignature": true,
  "verificationError": "",
  "healthCertificate": {
    "credentialVersion": 1,
    "issuer": "NL",
    "issuedAt": 1629283876,
    "expirationTime": 1672531200,
    "dcc":{"ver":"1.3.0","dob":"1990-01-01","nam":{"fn":"Doe","fnt":"DOE","gn":"John","gnt":"JOHN"},"v":[{"tg":"840539006","vp":"1119349007","mp":"EU/1/20/1528","ma":"ORG-100030215","dn":2,"sd":2,"dt":"2021-08-02","co":"NL","is":"Ministry of Health Welfare and Sport","ci":"URN:UCI:01:NL:ABCDEFGHIJKLMNO"}]}
  }
}
```

If `validSignature` is `false`, `verificationError` will contain the reason the signature is not valid. If `validSignature` is `true`, the `verificationError` is guaranteed to be empty.

## Maintainers

* Tomas Harreveld
