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

package sthgetter

import (
	"reflect"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/testonly"
)

var (
	// A valid STH from the Google Pilot Log.
	validSTH = &ct.GetSTHResponse{
		TreeSize:          580682455,
		Timestamp:         1554897886201, // 2019-04-10 12:04:46.201 UTC
		SHA256RootHash:    testonly.MustB64Decode("VicMkhzrGNv+lNCwXRVHH0WniZuDg3IXhgPai5kyHdA="),
		TreeHeadSignature: testonly.MustB64Decode("BAMARzBFAiEAs0GiYnPT5ZQJ2LGLhLmIXZXSLg+N+CxTkJL75tECEqgCIBZzJGyzH9h+IL63XCvRlfTKhLvzSxVicrT30+rwTSU0"),
	}
	// The public key for the Google Pilot Log.
	b64PubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA=="
	// A time less than 24 hours after the timestamp of validSTH.  If validSTH
	// was received at this time, it would not be considered 'too old'.
	validReceiveTime   = time.Date(2019, time.April, 10, 15, 0, 0, 0, time.UTC)
	invalidReceiveTime = time.Date(2019, time.April, 11, 15, 0, 0, 0, time.UTC)
)

func TestCheckSTH(t *testing.T) {
	// Create Log structure.
	l, err := ctlog.New("https://ct.googleapis.com", "google_pilot", b64PubKey, 24*time.Hour, nil)
	if err != nil {
		t.Fatalf("Unable to obtain Log metadata: %s", err)
	}

	// Create signature verifier.
	sv, err := ct.NewSignatureVerifier(l.PublicKey)
	if err != nil {
		t.Fatalf("Couldn't create signature verifier: %s", err)
	}

	tests := []struct {
		desc         string
		sth          *ct.GetSTHResponse
		receivedAt   time.Time
		wantErrTypes []reflect.Type
	}{
		{
			desc:       "valid",
			sth:        validSTH,
			receivedAt: validReceiveTime,
		},
		{
			desc: "invalid signature",
			// STH with TreeSize modified (set to 0) so that signature will not
			// verify.
			sth: &ct.GetSTHResponse{
				Timestamp:         validSTH.Timestamp,
				SHA256RootHash:    validSTH.SHA256RootHash,
				TreeHeadSignature: validSTH.TreeHeadSignature,
			},
			receivedAt: validReceiveTime,
			wantErrTypes: []reflect.Type{
				reflect.TypeOf(&SignatureVerificationError{}),
			},
		},
		{
			desc:       "old STH",
			sth:        validSTH,
			receivedAt: invalidReceiveTime,
			wantErrTypes: []reflect.Type{
				reflect.TypeOf(&OldTimestampError{}),
			},
		},
		{
			desc: "invalid sig and old STH",
			sth: &ct.GetSTHResponse{
				Timestamp:         validSTH.Timestamp,
				SHA256RootHash:    validSTH.SHA256RootHash,
				TreeHeadSignature: validSTH.TreeHeadSignature,
			},
			receivedAt: invalidReceiveTime,
			wantErrTypes: []reflect.Type{
				reflect.TypeOf(&SignatureVerificationError{}),
				reflect.TypeOf(&OldTimestampError{}),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			sth, err := test.sth.ToSignedTreeHead()
			if err != nil {
				t.Fatalf("error converting ct.GetSTHResponse to ct.SignedTreeHead: %s", err)
			}

			errs := checkSTH(sth, test.receivedAt, sv, l)
			if len(errs) != len(test.wantErrTypes) {
				t.Fatalf("checkSTH(%v, %v, _, _) = %v (%d errors), want errors of types %v (%d errors)", sth, test.receivedAt, errs, len(errs), test.wantErrTypes, len(test.wantErrTypes))
			}

			// Slightly brittle test: Relies on the order of the returned slice
			// of errors from checkSTH().
			for i, err := range errs {
				if got := reflect.TypeOf(err); got != test.wantErrTypes[i] {
					t.Errorf("The error at position %d is of type %v, want error of type %v", i, got, test.wantErrTypes[i])
				}
			}
		})
	}
}

func TestCheckSTHTimestamp(t *testing.T) {
	tests := []struct {
		desc         string
		sthTimestamp time.Time
		receivedAt   time.Time
		mmd          time.Duration
		wantErr      bool
	}{
		{
			desc:         "STH less than MMD old",
			sthTimestamp: time.Date(2019, time.January, 1, 0, 0, 0, 0, time.UTC),
			receivedAt:   time.Date(2019, time.January, 1, 12, 0, 0, 0, time.UTC),
			mmd:          24 * time.Hour,
		},
		{
			desc:         "STH exactly MMD old",
			sthTimestamp: time.Date(2019, time.January, 1, 0, 0, 0, 0, time.UTC),
			receivedAt:   time.Date(2019, time.January, 2, 0, 0, 0, 0, time.UTC),
			mmd:          24 * time.Hour,
		},
		{
			desc:         "STH just greater than MMD old",
			sthTimestamp: time.Date(2019, time.January, 1, 0, 0, 0, 0, time.UTC),
			receivedAt:   time.Date(2019, time.January, 2, 0, 0, 0, 1, time.UTC),
			mmd:          24 * time.Hour,
			wantErr:      true,
		},
		{
			desc:         "STH greater than MMD old",
			sthTimestamp: time.Date(2019, time.January, 1, 0, 0, 0, 0, time.UTC),
			receivedAt:   time.Date(2019, time.January, 2, 12, 0, 0, 0, time.UTC),
			mmd:          24 * time.Hour,
			wantErr:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			sth := &ct.SignedTreeHead{
				Timestamp: uint64(test.sthTimestamp.UnixNano() / time.Millisecond.Nanoseconds()),
			}
			err := checkSTHTimestamp(sth, test.receivedAt, test.mmd)
			if gotErr := (err != nil); gotErr != test.wantErr {
				t.Fatalf("checkSTHTimestamp(%v, %v, %v) = %v, want err? %t", sth, test.receivedAt, test.mmd, err, test.wantErr)
			}
		})
	}
}
