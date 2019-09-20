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

package interval

import (
	"testing"
	"time"
)

func TestRandomSecond(t *testing.T) {
	tests := []struct {
		desc     string
		in       *Interval
		wantZero bool
	}{
		{
			desc:     "nil",
			in:       nil,
			wantZero: true,
		},
		{
			desc: "day",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 26, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			desc: "second",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 1, 0, time.UTC),
			},
		},
		{
			desc: "one second boundary between",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 999999999, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 1, 1, time.UTC),
			},
		},
		{
			desc: "one second boundary between, start on second boundary",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 0, 1, time.UTC),
			},
		},
		{
			desc: "no second boundaries between",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 1, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 0, 999999999, time.UTC),
			},
			wantZero: true,
		},
		{
			desc: "no second boundaries between, end on second boundary",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 1, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 1, 0, time.UTC),
			},
			wantZero: true,
		},
		{
			desc: "equal",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
			},
			wantZero: true,
		},
		{
			desc: "end just before start",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 1, time.UTC),
				End:   time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
			},
			wantZero: true,
		},
		{
			desc: "end way before start",
			in: &Interval{
				Start: time.Date(2019, time.March, 25, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2019, time.March, 24, 0, 0, 0, 0, time.UTC),
			},
			wantZero: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got := test.in.RandomSecond()

			if test.wantZero {
				if !got.IsZero() {
					t.Fatalf("%v.RandomSecond() = %s, want %s (the zero time)", test.in, got, time.Time{})
				}
				return
			}

			if got.Before(test.in.Start) || !test.in.End.After(got) {
				t.Fatalf("%v.RandomSecond() = %s, want between [%s, %s)", test.in, got, test.in.Start, test.in.End)
			}
		})
	}
}
