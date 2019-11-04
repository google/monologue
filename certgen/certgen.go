// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package certgen generates (pre-)certificates and (pre-)certificate chains.
package certgen

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/monologue/interval"
)

const (
	keySizeBits  = 2048
	certValidity = time.Hour * 24
)

var timeNowUTC = func() time.Time {
	return time.Now().UTC()
}

// CertificateConfig contains details to be used to populate newly created leaf
// certificates.
type CertificateConfig struct {
	// Required fields
	//
	// What these are set to, including the zero values if left unset, is what
	// will appear in the leaf certificates.
	SubjectCommonName         string
	SubjectOrganization       string
	SubjectOrganizationalUnit string
	SubjectLocality           string
	SubjectCountry            string
	SignatureAlgorithm        x509.SignatureAlgorithm

	// Optional fields

	// DNSPrefix is a prefix that will be used in conjunction with the
	// SubjectCommonName to create a more specific DNS SAN.
	DNSPrefix string
	// NotAfterInterval specifies an interval in which the NotAfter time of a
	// certificate must fall.
	//
	// For example, if a certificate is being generated to be submitted to a
	// temporal CT Log shard, then, in order to be accepted by the Log, its
	// NotAfter value must fall within the Log's temporal range, so this field
	// would be set to the temporal interval of the Log.  However, if a
	// certificate is being generated to be submitted to a non-temporal CT Log,
	// this field should be left unset/set to nil.
	NotAfterInterval *interval.Interval
}

// CA is a Certificate Authority that issues certificates and certificate chains
// using its SigningCert and SigningKey.
type CA struct {
	SigningCert *x509.Certificate
	SigningKey  crypto.Signer
	CertConfig  CertificateConfig
}

// IssueCertificate creates a new leaf certificate, issued by the key specified
// in the SigningCert and SigningKey fields of the CA, and configured using the
// CertConfig in the CA.
func (ca *CA) IssueCertificate() (*x509.Certificate, error) {
	key, err := rsa.GenerateKey(crand.Reader, keySizeBits)
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %s", err)
	}

	template, err := leafTemplate(ca.CertConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating leaf template: %s", err)
	}

	leafDER, err := x509.CreateCertificate(crand.Reader, template, ca.SigningCert, key.Public(), ca.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("error creating leaf certificate: %s", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("error parsing leaf certificate DER: %s", err)
	}

	return leaf, nil
}

// IssueCertificateChain creates a new certificate chain, containing a new leaf
// certificate (as created by IssueCertificate) and the certificate for the key
// that signed it (stored in the SigningCert field of the CA).
func (ca *CA) IssueCertificateChain() ([]*x509.Certificate, error) {
	leaf, err := ca.IssueCertificate()
	if err != nil {
		return nil, fmt.Errorf("error issuing leaf certificate: %s", err)
	}

	return []*x509.Certificate{leaf, ca.SigningCert}, nil
}

func leafTemplate(c CertificateConfig) (*x509.Certificate, error) {
	sn, err := randSerialNumber()
	if err != nil {
		return nil, err
	}

	notAfter := timeNowUTC().Add(certValidity)
	if c.NotAfterInterval != nil {
		notAfter = c.NotAfterInterval.RandomSecond()
	}

	return &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Country:            []string{c.SubjectCountry},
			Organization:       []string{c.SubjectOrganization},
			OrganizationalUnit: []string{c.SubjectOrganizationalUnit},
			Locality:           []string{c.SubjectLocality},
			CommonName:         c.SubjectCommonName,
		},
		NotBefore:          notAfter.Add(-certValidity),
		NotAfter:           notAfter,
		SignatureAlgorithm: c.SignatureAlgorithm,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{c.SubjectCommonName, extendedDNSSAN(c.DNSPrefix, c.SubjectCommonName)},
	}, nil
}

func randSerialNumber() (*big.Int, error) {
	i := big.NewInt(0)
	return crand.Int(crand.Reader, i.SetUint64(math.MaxUint64))
}

// extendedDNSSAN creates a string to be used in the DNSNames SAN.  The string
// created is or the format <hour>.<day>.<month>.<year>.<prefix>.<url> where the
// time elements are based on the time now.  For example, if
// extendedDNSSAN(squirrel, example.com) was called at 2019-03-25 12:00 UTC, it
// would return 12.25.03.2019.squirrel.example.com
func extendedDNSSAN(prefix string, url string) string {
	now := timeNowUTC()
	dns := []string{
		fmt.Sprintf("%02d", now.Hour()),
		fmt.Sprintf("%02d", now.Day()),
		fmt.Sprintf("%02d", int(now.Month())),
		strconv.Itoa(now.Year()),
	}
	if prefix != "" {
		dns = append(dns, prefix)
	}
	dns = append(dns, url)
	return strings.Join(dns, ".")
}
