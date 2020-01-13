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

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/testonly"
)

func TestCheckSCT(t *testing.T) {
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
				reflect.TypeOf(&NotV1Error{}),
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

			errs := checkSCT(sct)
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
