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

package rootsanalyzer

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-cmp/cmp"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"

	itestonly "github.com/google/monologue/incident/testonly"
	stestonly "github.com/google/monologue/storage/testonly"
)

var (
	root1 = mustParseCert(`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`)
	root2 = mustParseCert(`MIIDyzCCArOgAwIBAgIDAOJIMA0GCSqGSIb3DQEBBQUAMIGLMQswCQYDVQQGEwJBVDFIMEYGA1UECgw/QS1UcnVzdCBHZXMuIGYuIFNpY2hlcmhlaXRzc3lzdGVtZSBpbSBlbGVrdHIuIERhdGVudmVya2VociBHbWJIMRgwFgYDVQQLDA9BLVRydXN0LVF1YWwtMDIxGDAWBgNVBAMMD0EtVHJ1c3QtUXVhbC0wMjAeFw0wNDEyMDIyMzAwMDBaFw0xNDEyMDIyMzAwMDBaMIGLMQswCQYDVQQGEwJBVDFIMEYGA1UECgw/QS1UcnVzdCBHZXMuIGYuIFNpY2hlcmhlaXRzc3lzdGVtZSBpbSBlbGVrdHIuIERhdGVudmVya2VociBHbWJIMRgwFgYDVQQLDA9BLVRydXN0LVF1YWwtMDIxGDAWBgNVBAMMD0EtVHJ1c3QtUXVhbC0wMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJaRq9eOsFm4Ab20Hq2Z/aH86gyWa48uSUjY6eQkguHYuszr3gdcSMYZggFHQgnhfLmfro/27l5rqKhWiDhWs+b+yZ1PNDhRPJy+86ycHMg9XJqErveULBSyZDdgjhSwOyrNibUir/fkf+4sKzP5jjytTKJXD/uCxY4fAd9TjMEVpN3umpIS0ijpYhclYDHvzzGU833z5Dwhq5D8bc9jp8YSAHFJ1xzIoO1jmn3jjyjdYPnY5harJtHQL73nDQnfbtTs5ThT9GQLulrMgLU4WeyAWWWEMWpfVZFMJOUkmoOEer6A8e5fIAeqdxdsC+JVqpZ4CAKel/Arrlj1gFA//jsCAwEAAaM2MDQwDwYDVR0TAQH/BAUwAwEB/zARBgNVHQ4ECgQIQj0rJKbBRc4wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUAA4IBAQBGyxFjUA2bPkXUSC2SfJ29tmrbiLKal+g6a9M8Xwd+Ejo+oYkNP6F4GfeDtAXpm7xb9Ly8lhdbHcpRhzCUQHJ1tBCiGdLgmhSx7TXjhhanKOdDgkdsC1T+++piuuYL72TDgUy2Sb1GHlJ1Nc6rvB4fpxSDAOHqGpUq9LWsc3tFkXqRqmQVtqtR77npKIFBioc62jTBwDMPX3hDJDR1DSPc6BnZliaNw2IHdiMQ0mBoYeRnFdq+TyDKsjmJOOQPLzzL/saaw6F891+gBjLFEFquDyR73lAPJS279R3csi8WWk4ZYUC/1V8H3Ktip/J6ac8eqhLCbmJ81Lo92JGHz/ot`)
)

func mustParseCert(b64CertDER string) *x509.Certificate {
	certDER, err := base64.StdEncoding.DecodeString(b64CertDER)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	return cert
}

func TestRootsChanged(t *testing.T) {
	rootSetID1 := storage.RootSetID("1")
	rootSetID2 := storage.RootSetID("2")

	l := &ctlog.Log{
		Name: "testtube",
		URL:  "https://ct.googleapis.com/testtube/",
	}

	tests := []struct {
		desc         string
		rootSetIDs   []storage.RootSetID
		rootSetCerts map[storage.RootSetID][]*x509.Certificate
		wantReport   *itestonly.Report
	}{
		{
			desc:       "no changes",
			rootSetIDs: []storage.RootSetID{rootSetID1, rootSetID1},
			rootSetCerts: map[storage.RootSetID][]*x509.Certificate{
				rootSetID1: {root1},
			},
		},
		{
			desc:       "1 cert added",
			rootSetIDs: []storage.RootSetID{rootSetID1, rootSetID2},
			rootSetCerts: map[storage.RootSetID][]*x509.Certificate{
				rootSetID1: {root1},
				rootSetID2: {root1, root2},
			},
			wantReport: &itestonly.Report{
				Summary:  "Root certificates changed",
				Category: "roots",
				BaseURL:  "https://ct.googleapis.com/testtube/",
				FullURL:  "https://ct.googleapis.com/testtube/ct/v1/get-roots",
				Details: `The root certificates accepted by testtube (https://ct.googleapis.com/testtube/) have changed.

Certificates added (1):
CN=A-Trust-Qual-02,OU=A-Trust-Qual-02,O=A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr GmbH,C=AT (SHA256: 75C9D4361CB96E993ABD9620CF043BE9407A4633F202F0F4C0E17851CC6089CD)
`,
			},
		},
		{
			desc:       "2 certs added",
			rootSetIDs: []storage.RootSetID{rootSetID1, rootSetID2},
			rootSetCerts: map[storage.RootSetID][]*x509.Certificate{
				rootSetID1: {},
				rootSetID2: {root1, root2},
			},
			wantReport: &itestonly.Report{
				Summary:  "Root certificates changed",
				Category: "roots",
				BaseURL:  "https://ct.googleapis.com/testtube/",
				FullURL:  "https://ct.googleapis.com/testtube/ct/v1/get-roots",
				Details: `The root certificates accepted by testtube (https://ct.googleapis.com/testtube/) have changed.

Certificates added (2):
CN=A-Trust-Qual-02,OU=A-Trust-Qual-02,O=A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr GmbH,C=AT (SHA256: 75C9D4361CB96E993ABD9620CF043BE9407A4633F202F0F4C0E17851CC6089CD)
CN=GLOBALTRUST,OU=GLOBALTRUST Certification Service,O=ARGE DATEN - Austrian Society for Data Protection,L=Vienna,ST=Austria,C=AT (SHA256: 5E3571F33F45A7DF1537A68B5FFB9E036AF9D2F5BC4C9717130DC43D7175AAC7)
`,
			},
		},
		{
			desc:       "1 cert removed",
			rootSetIDs: []storage.RootSetID{rootSetID1, rootSetID2},
			rootSetCerts: map[storage.RootSetID][]*x509.Certificate{
				rootSetID1: {root1, root2},
				rootSetID2: {root1},
			},
			wantReport: &itestonly.Report{
				Summary:  "Root certificates changed",
				Category: "roots",
				BaseURL:  "https://ct.googleapis.com/testtube/",
				FullURL:  "https://ct.googleapis.com/testtube/ct/v1/get-roots",
				Details: `The root certificates accepted by testtube (https://ct.googleapis.com/testtube/) have changed.

Certificates removed (1):
CN=A-Trust-Qual-02,OU=A-Trust-Qual-02,O=A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr GmbH,C=AT (SHA256: 75C9D4361CB96E993ABD9620CF043BE9407A4633F202F0F4C0E17851CC6089CD)
`,
			},
		},
		{
			desc:       "2 certs removed",
			rootSetIDs: []storage.RootSetID{rootSetID1, rootSetID2},
			rootSetCerts: map[storage.RootSetID][]*x509.Certificate{
				rootSetID1: {root1, root2},
				rootSetID2: {},
			},
			wantReport: &itestonly.Report{
				Summary:  "Root certificates changed",
				Category: "roots",
				BaseURL:  "https://ct.googleapis.com/testtube/",
				FullURL:  "https://ct.googleapis.com/testtube/ct/v1/get-roots",
				Details: `The root certificates accepted by testtube (https://ct.googleapis.com/testtube/) have changed.

Certificates removed (2):
CN=A-Trust-Qual-02,OU=A-Trust-Qual-02,O=A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr GmbH,C=AT (SHA256: 75C9D4361CB96E993ABD9620CF043BE9407A4633F202F0F4C0E17851CC6089CD)
CN=GLOBALTRUST,OU=GLOBALTRUST Certification Service,O=ARGE DATEN - Austrian Society for Data Protection,L=Vienna,ST=Austria,C=AT (SHA256: 5E3571F33F45A7DF1537A68B5FFB9E036AF9D2F5BC4C9717130DC43D7175AAC7)
`,
			},
		},
		{
			desc:       "1 cert added, 1 cert removed",
			rootSetIDs: []storage.RootSetID{rootSetID1, rootSetID2},
			rootSetCerts: map[storage.RootSetID][]*x509.Certificate{
				rootSetID1: {root1},
				rootSetID2: {root2},
			},
			wantReport: &itestonly.Report{
				Summary:  "Root certificates changed",
				Category: "roots",
				BaseURL:  "https://ct.googleapis.com/testtube/",
				FullURL:  "https://ct.googleapis.com/testtube/ct/v1/get-roots",
				Details: `The root certificates accepted by testtube (https://ct.googleapis.com/testtube/) have changed.

Certificates added (1):
CN=A-Trust-Qual-02,OU=A-Trust-Qual-02,O=A-Trust Ges. f. Sicherheitssysteme im elektr. Datenverkehr GmbH,C=AT (SHA256: 75C9D4361CB96E993ABD9620CF043BE9407A4633F202F0F4C0E17851CC6089CD)

Certificates removed (1):
CN=GLOBALTRUST,OU=GLOBALTRUST Certification Service,O=ARGE DATEN - Austrian Society for Data Protection,L=Vienna,ST=Austria,C=AT (SHA256: 5E3571F33F45A7DF1537A68B5FFB9E036AF9D2F5BC4C9717130DC43D7175AAC7)
`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			test := test
			t.Parallel()

			fakeStorage := &stestonly.FakeRootsReader{
				RootSetChan:  make(chan storage.RootSetID, len(test.rootSetIDs)),
				RootSetCerts: test.rootSetCerts,
			}
			fakeReporter := &itestonly.FakeReporter{
				Updates: make(chan itestonly.Report, 1),
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			go Run(ctx, fakeStorage, fakeReporter, l)

			for _, id := range test.rootSetIDs {
				fakeStorage.RootSetChan <- id
			}

			select {
			case <-ctx.Done():
				if test.wantReport != nil {
					t.Errorf("No incident report received before context expired")
				}
			case report := <-fakeReporter.Updates:
				if diff := cmp.Diff(&report, test.wantReport); diff != "" {
					t.Errorf("Incident report diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}
