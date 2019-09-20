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

// Package interval provides a struct representing a time interval.
package interval

import (
	"math/rand"
	"time"
)

// Interval represents the interval [Start, End).
type Interval struct {
	Start, End time.Time
}

// RandomInstant returns a random time (to second precision) that falls within
// the Interval.
//
// If the Interval is nil, or Interval.End <= Interval.Start, the zero value
// time.Time will be returned.
func (i *Interval) RandomInstant() time.Time {
	if i == nil {
		return time.Time{}
	}

	if i.Start.Equal(i.End) || i.Start.After(i.End) {
		return time.Time{}
	}

	start := i.Start.Unix()
	end := i.End.Unix()
	delta := end - start

	if delta == 0 {
		return i.Start
	}

	rand.Seed(time.Now().UnixNano())
	return time.Unix(start+rand.Int63n(delta), 0)
}
