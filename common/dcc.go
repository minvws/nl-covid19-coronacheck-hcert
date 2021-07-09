package common

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
)

type DCC struct {
	Version     string `cbor:"ver" json:"ver"`
	DateOfBirth string `cbor:"dob" json:"dob"`

	Name         *DCCName          `cbor:"nam" json:"nam"`
	Vaccinations []*DCCVaccination `cbor:"v,omitempty" json:"v"`
	Tests        []*DCCTest        `cbor:"t,omitempty" json:"t"`
	Recoveries   []*DCCRecovery    `cbor:"r,omitempty" json:"r"`
}

type DCCName struct {
	FamilyName             string `cbor:"fn" json:"fn"`
	StandardizedFamilyName string `cbor:"fnt" json:"fnt"`
	GivenName              string `cbor:"gn" json:"gn"`
	StandardizedGivenName  string `cbor:"gnt" json:"gnt"`
}

type DCCVaccination struct {
	DiseaseTargeted       string `cbor:"tg" json:"tg"`
	Vaccine               string `cbor:"vp" json:"vp"`
	MedicinalProduct      string `cbor:"mp" json:"mp"`
	Manufacturer          string `cbor:"ma" json:"ma"`
	DoseNumber            int    `cbor:"dn" json:"dn"`
	TotalSeriesOfDoses    int    `cbor:"sd" json:"sd"`
	DateOfVaccination     string `cbor:"dt" json:"dt"`
	CountryOfVaccination  string `cbor:"co" json:"co"`
	CertificateIssuer     string `cbor:"is" json:"is"`
	CertificateIdentifier string `cbor:"ci" json:"ci"`
}

type DCCTest struct {
	DiseaseTargeted         string `cbor:"tg" json:"tg"`
	TypeOfTest              string `cbor:"tt" json:"tt"`
	TestName                string `cbor:"nm,omitempty" json:"nm"`
	TestNameAndManufacturer string `cbor:"ma,omitempty" json:"ma"`
	DateTimeOfCollection    string `cbor:"sc" json:"sc"`
	TestResult              string `cbor:"tr" json:"tr"`
	TestingCentre           string `cbor:"tc" json:"tc"`
	CountryOfVaccination    string `cbor:"co" json:"co"`
	CertificateIssuer       string `cbor:"is" json:"is"`
	CertificateIdentifier   string `cbor:"ci" json:"ci"`
}

type DCCRecovery struct {
	DiseaseTargeted         string `cbor:"tg" json:"tg"`
	DateOfFirstPositiveTest string `cbor:"fr" json:"fr"`
	CountryOfTest           string `cbor:"co" json:"co"`
	CertificateIssuer       string `cbor:"is" json:"is"`
	CertificateValidFrom    string `cbor:"df" json:"df"`
	CertificateValidUntil   string `cbor:"du" json:"du"`
	CertificateIdentifier   string `cbor:"ci" json:"ci"`
}

func ReadDCC(dccCbor []byte) (dcc *DCC, err error) {
	err = cbor.Unmarshal(dccCbor, &dcc)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not cbor unmarshal DCC", 0)
	}

	return dcc, nil
}
