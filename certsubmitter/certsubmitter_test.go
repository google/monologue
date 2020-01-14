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

package certsubmitter

import (
	"reflect"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/interval"
	"github.com/google/monologue/testonly"
)

var (
	url     = "https://ct.googleapis.com/logs/xenon2019/"
	name    = "google_xenon2019"
	pubKey  = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/XyDwqzXL9i2GTjMYkqaEyiRL0Dy9sHq/BTebFdshbvCaXXEh6mjUK0Yy+AsDcI4MpzF1l7Kded2MD5zi420gA=="
	mmd     = 24 * time.Hour
	tempInt = &interval.Interval{
		Start: time.Date(2019, time.January, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
)

func TestCheckSCT(t *testing.T) {
	ctl, err := ctlog.New(url, name, pubKey, mmd, tempInt)
	if err != nil {
		t.Fatalf("ctlog.New(%s, %s, %s, %s, %v) = _, %s", url, name, pubKey, mmd, tempInt, err)
	}

	tests := []struct {
		desc         string
		sct          *ct.AddChainResponse
		wantErrTypes []reflect.Type
	}{
		{
			desc: "SCT not v1",
			sct: &ct.AddChainResponse{
				SCTVersion: 1,
				ID:         testonly.MustB64Decode("CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA="),
				Timestamp:  0,
				Signature:  testonly.MustB64Decode("BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="),
			},
			wantErrTypes: []reflect.Type{
				reflect.TypeOf(&V1Error{}),
			},
		},
		{
			desc: "SCT contains wrong LogID",
			sct: &ct.AddChainResponse{
				ID:        testonly.MustB64Decode("B7dcG+V9aP/xsMYdIxXHuuZXfFeUt2ruvGE6GmnTohw="),
				Timestamp: 0,
				Signature: testonly.MustB64Decode("BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="),
			},
			wantErrTypes: []reflect.Type{
				reflect.TypeOf(&LogIDError{}),
			},
		},
		{
			desc: "no errors",
			sct: &ct.AddChainResponse{
				ID:        testonly.MustB64Decode("CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA="),
				Timestamp: 0,
				Signature: testonly.MustB64Decode("BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			sct, err := test.sct.ToSignedCertificateTimestamp()
			if err != nil {
				t.Fatalf("error converting ct.AddChainResponse to ct.SignedCertificateTimestamp: %s", err)
			}

			errs := checkSCT(sct, ctl)
			if len(errs) != len(test.wantErrTypes) {
				t.Fatalf("checkSCT(%v) = %v (%d errors), want errors of types %v (%d errors)", sct, errs, len(errs), test.wantErrTypes, len(test.wantErrTypes))
			}

			// Slightly brittle test: Relies on the order of the returned slice
			// of errors from checkSCT().
			for i, err := range errs {
				if got := reflect.TypeOf(err); got != test.wantErrTypes[i] {
					t.Errorf("The error at position %d is of type %v, want error of type %v", i, got, test.wantErrTypes[i])
				}
			}
		})
	}
}
