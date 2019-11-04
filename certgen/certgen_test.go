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
)

var certConfig = CertificateConfig{
	SubjectCommonName:         "test-leaf-certificate",
	SubjectOrganization:       "Test Organisation",
	SubjectOrganizationalUnit: "Test Organisational Unit",
	SubjectLocality:           "Test Locality",
	SubjectCountry:            "GB",
	SignatureAlgorithm:        x509.SHA256WithRSA,
	DNSPrefix:                 "test-log",
}

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
			cc := certConfig
			cc.NotAfterInterval = test.notAfterInterval
			ca := &CA{SigningCert: root, SigningKey: rootKey, CertConfig: cc}

			cert, err := ca.IssueCertificate()
			if err != nil {
				t.Fatalf("error creating certificate: %s", err)
			}

			// Check the fields that are set in the leaf template are present
			// and correct.

			if cert.SerialNumber == nil {
				t.Error("certificate Serial Number is nil")
			}

			// Check the Subject fields.
			if got, want := cert.Subject.Country, []string{cc.SubjectCountry}; !cmp.Equal(got, want) {
				t.Errorf("certificate Subject Country = %v, want %v", got, want)
			}
			if got, want := cert.Subject.Organization, []string{cc.SubjectOrganization}; !cmp.Equal(got, want) {
				t.Errorf("certificate Subject Organization = %v, want %v", got, want)
			}
			if got, want := cert.Subject.OrganizationalUnit, []string{cc.SubjectOrganizationalUnit}; !cmp.Equal(got, want) {
				t.Errorf("certificate Subject OrganizationalUnit = %v, want %v", got, want)
			}
			if got, want := cert.Subject.Locality, []string{cc.SubjectLocality}; !cmp.Equal(got, want) {
				t.Errorf("certificate Subject Locality = %v, want %v", got, want)
			}
			if got, want := cert.Subject.CommonName, cc.SubjectCommonName; got != want {
				t.Errorf("certificate Subject Common Name = %s, want %s", got, want)
			}

			// Check the validity period fields.
			if cert.NotBefore.IsZero() {
				t.Error("certificate NotBefore is the zero time")
			}
			if got, want := cert.NotBefore, cert.NotAfter.Add(-certValidity); got != want {
				t.Errorf("certificate NotBefore = %s, want %s (%s before Not After)", got, want, certValidity)
			}
			if cert.NotAfter.IsZero() {
				t.Error("certificate NotAfter is the zero time")
			}
			if cc.NotAfterInterval != nil {
				// Check that cert.NotAfter is in the NotAfterInterval [Start, End).
				if got := cert.NotAfter; got.Before(cc.NotAfterInterval.Start) || !cc.NotAfterInterval.End.After(got) {
					t.Errorf("certificate NotAfter = %s, should be between [%s, %s)", got, cc.NotAfterInterval.Start, cc.NotAfterInterval.End)
				}
			}

			// Check the extension fields.
			if got, want := cert.KeyUsage, x509.KeyUsageDigitalSignature; got != want {
				t.Errorf("certificate KeyUsage = %d, want %d", got, want)
			}
			if got, want := cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}; !cmp.Equal(got, want) {
				t.Errorf("certificate ExtKeyUsage = %v, want %v", got, want)
			}
			if !cert.BasicConstraintsValid {
				t.Errorf("certificate BasicConstraintsValid = %t, want true", cert.BasicConstraintsValid)
			}
			if cert.IsCA {
				t.Errorf("certificate IsCA = %t, want false", cert.IsCA)
			}

			want := []string{cc.SubjectCommonName, extendedDNSSAN(cc.DNSPrefix, cc.SubjectCommonName)}
			if got := cert.DNSNames; !cmp.Equal(got, want) {
				t.Errorf("certificate DNSNames = %v, want %v", got, want)
			}

			// Check any other fields that should have been populated are
			// present and correct.

			if got, want := cert.PublicKeyAlgorithm, x509.RSA; got != want {
				t.Errorf("certificate PublicKeyAlgorithm = %s, want %s", got, want)
			}
			if cert.PublicKey == nil {
				t.Error("certificate Public Key is nil")
			}
			if got, want := cert.Issuer, root.Subject; !cmp.Equal(got, want) {
				t.Errorf("certificate Issuer = %v, want %v", got, want)
			}
			if got, want := cert.AuthorityKeyId, root.SubjectKeyId; !bytes.Equal(got, want) {
				t.Errorf("certificate AuthorityKeyId = %v, want %v", got, want)
			}

			// Check the signature algorithm.
			if got, want := cert.SignatureAlgorithm, cc.SignatureAlgorithm; got != want {
				t.Errorf("certificate SignatureAlgorithm = %s, want %s", got, want)
			}

			// Check the signature is valid.
			if err := cert.CheckSignatureFrom(root); err != nil {
				t.Errorf("certificate signature doesn't verify: %s", err)
			}
		})
	}
}

func TestIssueCertificateChain(t *testing.T) {
	root, rootKey, err := rootAndKeySetup(rootFile, rootKeyFile)
	if err != nil {
		t.Fatalf("root and key setup error: %s", err)
	}
	cc := certConfig
	cc.NotAfterInterval = &interval.Interval{
		Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2020, time.March, 25, 0, 0, 0, 0, time.UTC),
	}
	ca := &CA{SigningCert: root, SigningKey: rootKey, CertConfig: cc}

	chain, err := ca.IssueCertificateChain()

	if err != nil {
		t.Fatalf("ca.IssueCertificateChain() = _, %q, want nil error", err)
	}

	if len(chain) != 2 {
		t.Fatalf("ca.IssueCertificateChain(): chain length = %d, want 2", len(chain))
	}

	if !chain[1].Equal(ca.SigningCert) {
		t.Fatalf("ca.IssueCertificateChain(): root of chain (%v) is not equal to ca.SigningCert (%v)", chain[1], ca.SigningCert)
	}

	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Errorf("ca.IssueCertificateChain(): leaf certificate signature doesn't verify against ca.SigningCert: %s", err)
	}
}

func TestExtendedDNSSAN(t *testing.T) {
	tests := []struct {
		desc    string
		timeNow time.Time
		prefix  string
		url     string
		want    string
	}{
		{
			desc:    "prefix",
			timeNow: time.Date(2019, time.March, 25, 12, 0, 0, 0, time.UTC),
			prefix:  "squirrel",
			url:     "example.com",
			want:    "12.25.03.2019.squirrel.example.com",
		},
		{
			desc:    "empty prefix",
			timeNow: time.Date(2019, time.January, 25, 12, 0, 0, 0, time.UTC),
			prefix:  "",
			url:     "example.com",
			want:    "12.25.01.2019.example.com",
		},
	}

	for _, test := range tests {
		timeNowUTC = func() time.Time {
			return test.timeNow
		}
		if got := extendedDNSSAN(test.prefix, test.url); got != test.want {
			t.Errorf("%s: extendedDNSSAN(%s, %s) = %s, want %s", test.desc, test.prefix, test.url, got, test.want)
		}
	}
}
