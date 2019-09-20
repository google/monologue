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

// RandomSecond returns a random second-precision time that falls within the
// Interval.
//
// If there is no second-precision time that falls in the Interval, the zero
// value time.Time will be returned.
// For example:
//    Start = 2019-03-25 00:00:00.1 +0000 UTC
//    End = 2019-03-25 00:00:00.9 +0000 UTC
//
// If Interval.End == Interval.Start, the zero value time.Time will be returned.
// This is because an Interval represents the interval
// [Interval.Start, Interval.End), so if Interval.Start and Interval.End are
// equal, the interval is invalid.
//
// If Interval.End < Interval.Start, the zero value time.Time will be returned.
//
// If the Interval is nil, the zero value time.Time will be returned.
func (i *Interval) RandomSecond() time.Time {
	if i == nil {
		return time.Time{}
	}

	if !i.Start.Before(i.End) {
		return time.Time{}
	}

	// Set start to be the first second boundary >= i.Start.
	start := i.Start.Unix()
	if i.Start.Nanosecond() != 0 {
		start++
	}

	// Set end to be the first second boundary >= i.End.
	end := i.End.Unix()
	if i.End.Nanosecond() != 0 {
		end++
	}

	delta := end - start

	// If delta == 0 there are no second boundaries in [i.Start, i.End). Return
	// the zero time.
	//
	// For example:
	//    Start = 2019-03-25 00:00:00.1 +0000 UTC
	//    End = 2019-03-25 00:00:00.9 +0000 UTC
	if delta == 0 {
		return time.Time{}
	}

	// Otherwise, there is at least one second boundary in [i.Start, i.End).
	// Randomly choose one of them, and return it.
	rand.Seed(time.Now().UnixNano())
	return time.Unix(start+rand.Int63n(delta), 0)
}
