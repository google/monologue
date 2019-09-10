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

package certgen

import (
	"bytes"
	"crypto"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/go-cmp/cmp"
	"github.com/google/monologue/interval"
	"github.com/google/trillian/crypto/keys/pem"
)

const (
	rootFile    = "./testdata/test_ca.pem"
	rootKeyFile = "./testdata/test_ca.key"

	subjectCommonName         = "test-leaf-certificate"
	subjectOrganization       = "Test Organisation"
	subjectOrganizationalUnit = "Test Organisational Unit"
	subjectLocality           = "Test Locality"
	subjectCountry            = "GB"
	signatureAlgorithm        = x509.SHA256WithRSA
	prefix                    = "test-log"
)

func rootAndKeySetup(rootFile, rootKeyFile string) (*x509.Certificate, crypto.Signer, error) {
	rootPEM, err := ioutil.ReadFile(rootFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading root cert: %s", err)
	}
	root, err := x509util.CertificateFromPEM(rootPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing root cert: %s", err)
	}

	rootKeyPEM, err := ioutil.ReadFile(rootKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading root key: %s", err)
	}
	rootKey, err := pem.UnmarshalPrivateKey(string(rootKeyPEM), "")
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing root key: %s", err)
	}

	return root, rootKey, nil
}

func TestIssueCertificate(t *testing.T) {
	tests := []struct {
		desc             string
		notAfterInterval *interval.Interval
	}{
		{
			desc: "not temporal",
		},
		{
			desc: "smallest temporal",
			notAfterInterval: &interval.Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 1, 0, time.UTC),
			},
		},
		{
			desc: "year temporal",
			notAfterInterval: &interval.Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2020, time.March, 25, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	root, rootKey, err := rootAndKeySetup(rootFile, rootKeyFile)
	if err != nil {
		t.Fatalf("root and key setup error: %s", err)
	}

	timeNowUTC = func() time.Time {
		return time.Date(2019, time.March, 25, 12, 0, 0, 0, time.UTC)
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			ca := &CA{
				RootCert: root,
				RootKey:  rootKey,
				CertConfig: CertificateConfig{
					SubjectCommonName:         subjectCommonName,
					SubjectOrganization:       subjectOrganization,
					SubjectOrganizationalUnit: subjectOrganizationalUnit,
					SubjectLocality:           subjectLocality,
					SubjectCountry:            subjectCountry,
					SignatureAlgorithm:        signatureAlgorithm,
					Prefix:                    prefix,
					NotAfterInterval:          test.notAfterInterval,
				},
			}

			cert, err := ca.IssueCertificate()
			if err != nil {
				t.Fatalf("error creating certificate: %s", err)
			}

			// Check the fields that are set in the leaf template are present
			// and correct.

			if cert.SerialNumber == nil {
				t.Error("certificate Serial Number is nil")
			}

			cc := ca.CertConfig
			// Check the Subject fields.
			if want := []string{cc.SubjectCountry}; !cmp.Equal(cert.Subject.Country, want) {
				t.Errorf("certificate Subject Country = %v, want %v", cert.Subject.Country, want)
			}
			if want := []string{cc.SubjectOrganization}; !cmp.Equal(cert.Subject.Organization, want) {
				t.Errorf("certificate Subject Organization = %v, want %v", cert.Subject.Organization, want)
			}
			if want := []string{cc.SubjectOrganizationalUnit}; !cmp.Equal(cert.Subject.OrganizationalUnit, want) {
				t.Errorf("certificate Subject OrganizationalUnit = %v, want %v", cert.Subject.OrganizationalUnit, want)
			}
			if want := []string{cc.SubjectLocality}; !cmp.Equal(cert.Subject.Locality, want) {
				t.Errorf("certificate Subject Locality = %v, want %v", cert.Subject.Locality, want)
			}
			if cert.Subject.CommonName != cc.SubjectCommonName {
				t.Errorf("certificate Subject Common Name = %s, want %s", cert.Subject.CommonName, cc.SubjectCommonName)
			}

			// Check the validity period fields.
			if cert.NotBefore.IsZero() {
				t.Error("certificate NotBefore is the zero time")
			}
			if want := cert.NotAfter.Add(time.Hour * -24); want != cert.NotBefore {
				t.Errorf("certificate NotBefore = %s, want %s (24 hours before Not After)", cert.NotBefore, want)
			}
			if cert.NotAfter.IsZero() {
				t.Error("certificate NotAfter is the zero time")
			}
			if cc.NotAfterInterval != nil {
				// Check that cert.NotAfter is in the NotAfterInterval [Start, End).
				if cert.NotAfter.Before(cc.NotAfterInterval.Start) || !cc.NotAfterInterval.End.After(cert.NotAfter) {
					t.Errorf("certificate NotAfter = %s, should be between [%s, %s)", cert.NotAfter, cc.NotAfterInterval.Start, cc.NotAfterInterval.End)
				}
			}

			// Check the extension fields.
			if cert.KeyUsage != x509.KeyUsageDigitalSignature {
				t.Errorf("certificate KeyUsage = %d, want %d", cert.KeyUsage, x509.KeyUsageDigitalSignature)
			}
			if want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}; !cmp.Equal(cert.ExtKeyUsage, want) {
				t.Errorf("certificate ExtKeyUsage = %v, want %v", cert.ExtKeyUsage, want)
			}
			if !cert.BasicConstraintsValid {
				t.Errorf("certificate BasicConstraintsValid = %t, want true", cert.BasicConstraintsValid)
			}
			if cert.IsCA {
				t.Errorf("certificate IsCA = %t, want false", cert.IsCA)
			}

			want := []string{cc.SubjectCommonName, extendedDNSSAN(cc.Prefix, cc.SubjectCommonName)}
			if !cmp.Equal(cert.DNSNames, want) {
				t.Errorf("certificate DNSNames = %v, want %v", cert.DNSNames, want)
			}

			// Check any other fields that should have been populated are
			// present and correct.

			if cert.PublicKeyAlgorithm != x509.RSA {
				t.Errorf("certificate PublicKeyAlgorithm = %s, want %s", cert.PublicKeyAlgorithm, x509.RSA)
			}
			if cert.PublicKey == nil {
				t.Error("certificate Public Key is nil")
			}
			if !cmp.Equal(cert.Issuer, root.Subject) {
				t.Errorf("certificate Issuer = %v, want %v", cert.Issuer, root.Subject)
			}
			if !bytes.Equal(cert.AuthorityKeyId, root.SubjectKeyId) {
				t.Errorf("certificate AuthorityKeyId = %v, want %v", cert.AuthorityKeyId, root.SubjectKeyId)
			}

			// Check the signature algorithm.
			if cert.SignatureAlgorithm != cc.SignatureAlgorithm {
				t.Errorf("certificate SignatureAlgorithm = %s, want %s", cert.SignatureAlgorithm, cc.SignatureAlgorithm)
			}

			// Check the signature is valid.
			if err := cert.CheckSignatureFrom(root); err != nil {
				t.Errorf("certificate signature doesn't verify: %s", err)
			}
		})
	}
}

func TestExtendedDNSSAN(t *testing.T) {
	tests := []struct {
		desc   string
		prefix string
		url    string
		want   string
	}{
		{
			desc:   "prefix",
			prefix: "google-pilot",
			url:    "flowers-to-the-world.com",
			want:   "12.25.march.2019.google-pilot.flowers-to-the-world.com",
		},
		{
			desc:   "empty prefix",
			prefix: "",
			url:    "flowers-to-the-world.com",
			want:   "12.25.march.2019.flowers-to-the-world.com",
		},
	}

	timeNowUTC = func() time.Time {
		return time.Date(2019, time.March, 25, 12, 0, 0, 0, time.UTC)
	}

	for _, test := range tests {
		if got := extendedDNSSAN(test.prefix, test.url); got != test.want {
			t.Errorf("%s: extendedDNSSAN(%s, %s) = %s, want %s", test.desc, test.prefix, test.url, got, test.want)
		}
	}
}
