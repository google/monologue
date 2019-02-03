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

// Package rootsgetter periodically queries a Log for its set of acceptable root certificates and stores them.
package rootsgetter

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"
)

const logStr = "Roots Getter"

// Storage interface required by Roots Getter.
type Storage interface {
	storage.APICallWriter
	storage.RootsWriter
}

// Run starts an STH Getter, which periodically queries a Log for its set of acceptable root certificates and stores them.
func Run(ctx context.Context, lc *client.LogClient, st Storage, l *ctlog.Log, period time.Duration) {
	glog.Infof("%s: %s: started with period %v", l.URL, logStr, period)

	schedule.Every(ctx, period, func(ctx context.Context) {
		roots, receivedAt, err := getRoots(ctx, lc, st, l)
		if err != nil {
			glog.Errorf("%s: %s: %s", l.URL, logStr, err)
		}
		if err := st.WriteRoots(ctx, l, roots, receivedAt); err != nil {
			glog.Errorf("%s: %s: %s", l.URL, logStr, err)
		}
	})

	glog.Infof("%s: %s: stopped", l.URL, logStr)
}

func getRoots(ctx context.Context, lc *client.LogClient, st storage.APICallWriter, l *ctlog.Log) ([]*x509.Certificate, time.Time, error) {
	glog.Infof("%s: %s: getting roots...", l.URL, logStr)
	roots, httpData, getErr := lc.GetRoots()

	// Store get-roots API call.
	apiCall := apicall.New(ct.GetRootsStr, httpData, getErr)
	glog.Infof("%s: %s: writing API Call...", l.URL, logStr)
	if err := st.WriteAPICall(ctx, l, apiCall); err != nil {
		return nil, httpData.Timing.End, fmt.Errorf("error writing API Call %s: %s", apiCall, err)
	}

	if getErr != nil {
		return nil, httpData.Timing.End, fmt.Errorf("error getting roots: %s", getErr)
	}

	glog.Infof("%s: %s: response: %d certificates", l.URL, logStr, len(roots))
	return roots, httpData.Timing.End, nil
}
