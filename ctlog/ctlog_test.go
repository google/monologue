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

package ctlog

import (
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
)

func TestNewTemporalInterval(t *testing.T) {
	tests := []struct {
		desc  string
		start time.Time
		end   time.Time
		want  Interval
	}{
		{
			desc:  "strip nanos",
			start: time.Date(2019, time.March, 25, 0, 0, 0, 1, time.UTC),
			end:   time.Date(2019, time.March, 25, 23, 59, 59, 999999999, time.UTC),
			want: Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 23, 59, 59, 0, time.UTC),
			},
		},
		{
			desc:  "no nanos",
			start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2019, time.March, 25, 23, 59, 59, 0, time.UTC),
			want: Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 23, 59, 59, 0, time.UTC),
			},
		},
	}

	url := "https://ct.googleapis.com/pilot"
	name := "google_pilot"
	b64PubKey := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA=="
	mmd := 24 * time.Hour

	for _, test := range tests {
		got, err := New(url, name, b64PubKey, mmd, test.start, test.end)
		if err != nil {
			t.Errorf("%s: New(%s, %s, %s, %s, %s, %s) = _, %s, want no error", test.desc, url, name, b64PubKey, mmd, test.start, test.end, err)
		}
		if diff := pretty.Compare(test.want, got.TemporalInterval); diff != "" {
			t.Errorf("%s: New(%s, %s, %s, %s, %s, %s) returned TemporalInterval diff (-want +got):\n%s", test.desc, url, name, b64PubKey, mmd, test.start, test.end, diff)
		}
	}
}
