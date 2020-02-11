// Copyright 2020 Google LLC
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
	"encoding/hex"
	"testing"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/monologue/storage"
	"github.com/google/monologue/testdata"
)

func TestCertIDOnNil(t *testing.T) {
	if _, gotErr := GenerateCertID(nil); gotErr == nil {
		t.Errorf("Error expected, got nil")
	}
}

func mustHexCode(s string, t *testing.T) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Errorf("Unexpected error while preparing testdata: %s", err)
	}
	return decoded
}

func TestCertIDOnValid(t *testing.T) {
	decoded := mustHexCode("86d8219c7e2b6009e37eb14356268489b81379e076e8f372e3dde8c162a34134", t)
	var wantID [32]byte
	copy(wantID[:], decoded[:32])
	cert, _ := x509util.CertificateFromPEM([]byte(testdata.RootCertPEM))

	gotCertID, gotErr := GenerateCertID(cert)
	if gotErr != nil {
		t.Errorf("Nil error expected, got %v", gotErr)
	}
	if gotCertID != wantID {
		t.Errorf("Got cert-ID %x for root certificate, want %x", string(gotCertID[:]), wantID)
	}
}

func TestGenerateSetID(t *testing.T) {
	cert, _ := x509util.CertificateFromPEM([]byte(testdata.RootCertPEM))
	cert2, _ := x509util.CertificateFromPEM([]byte(testdata.IntermediateCertPEM))

	tests := []struct {
		desc      string
		roots     []*x509.Certificate
		wantSetID storage.RootSetID
	}{
		{
			desc:      "SingleRoot",
			roots:     []*x509.Certificate{cert},
			wantSetID: storage.RootSetID(mustHexCode("35d1cd6dbd84a37a5884351d1d0d197d2e9048709b1442391cdfac69f8371272", t)),
		},
		{
			desc:      "DedupRoot",
			roots:     []*x509.Certificate{cert, cert, cert},
			wantSetID: storage.RootSetID(mustHexCode("35d1cd6dbd84a37a5884351d1d0d197d2e9048709b1442391cdfac69f8371272", t)),
		},
		{
			desc:      "TwoCerts",
			roots:     []*x509.Certificate{cert, cert2},
			wantSetID: storage.RootSetID(mustHexCode("be6b3e0736f965cf707eb773709027a7250de5e32910f09370146d1318d6df04", t)),
		},
		{
			desc:      "TwoCertsSort",
			roots:     []*x509.Certificate{cert2, cert},
			wantSetID: storage.RootSetID(mustHexCode("be6b3e0736f965cf707eb773709027a7250de5e32910f09370146d1318d6df04", t)),
		},
		{
			desc:      "TwoCertsSortDedup",
			roots:     []*x509.Certificate{cert2, cert, cert, cert2},
			wantSetID: storage.RootSetID(mustHexCode("be6b3e0736f965cf707eb773709027a7250de5e32910f09370146d1318d6df04", t)),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotSetID, gotErr := GenerateSetID(test.roots)
			if gotErr != nil {
				t.Fatalf("Nil error expected, got %v", gotErr)
			}
			if gotSetID != test.wantSetID {
				t.Errorf("Got cert-ID %x for root certificate, want %x", string(gotSetID), test.wantSetID)
			}
		})
	}
}
