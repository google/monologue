// Copyright 2018 Google LLC
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

package apicall

import (
	"net/http"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-monitor/client"
	"github.com/google/go-cmp/cmp"
)

func TestNew(t *testing.T) {
	pilotGetSTH := "https://ct.googleapis.com/pilot/ct/v1/get-sth"

	tests := []struct {
		name     string
		endpoint ct.APIEndpoint
		httpData *client.HTTPData
		err      error
		want     *APICall
	}{
		{
			name:     "nil httpData",
			endpoint: ct.GetSTHStr,
			err:      &client.NilResponseError{URL: pilotGetSTH},
			want: &APICall{
				Endpoint: ct.GetSTHStr,
				Err:      &client.NilResponseError{URL: pilotGetSTH},
			},
		},
		{
			name:     "no error",
			endpoint: ct.GetSTHStr,
			httpData: &client.HTTPData{
				Timing: client.Timing{
					Start: time.Date(2018, time.August, 21, 14, 12, 0, 0, time.UTC),
					End:   time.Date(2018, time.August, 21, 14, 14, 0, 0, time.UTC),
				},
				Response: &http.Response{StatusCode: http.StatusOK},
				Body:     []byte("some bytes"),
			},
			want: &APICall{
				Start:    time.Date(2018, time.August, 21, 14, 12, 0, 0, time.UTC),
				End:      time.Date(2018, time.August, 21, 14, 14, 0, 0, time.UTC),
				Endpoint: ct.GetSTHStr,
				Response: &http.Response{StatusCode: http.StatusOK},
				Body:     []byte("some bytes"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := New(test.endpoint, test.httpData, test.err)
			if diff := cmp.Diff(got, test.want); diff != "" {
				t.Errorf("CreateAPICall(): diff: (-got +want)\n%s", diff)
			}
		})
	}
}
