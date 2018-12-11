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
	"log"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"
)

const logStr = "Roots Getter"

// Run starts an STH Getter, which periodically queries a Log for its set of acceptable root certificates and stores them.
func Run(ctx context.Context, lc *client.LogClient, st storage.APICallWriter, l *ctlog.Log, period time.Duration) {
	log.Printf("%s: %s: started with period %v", l.URL, logStr, period)

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// TODO(katjoyce): Work out when and where to add context timeouts.
			getAndStoreRoots(ctx, lc, st, l)
		case <-ctx.Done():
			log.Printf("%s: %s: stopped", l.URL, logStr)
			return
		}
	}
}

func getAndStoreRoots(ctx context.Context, lc *client.LogClient, st storage.APICallWriter, l *ctlog.Log) {
	log.Printf("%s: %s: getting roots...", l.URL, logStr)
	roots, httpData, getErr := lc.GetRoots()
	if getErr != nil {
		log.Printf("%s: %s: error getting roots: %s", l.URL, logStr, getErr)
	} else {
		log.Printf("%s: %s: response: %d certificates", l.URL, logStr, len(roots))
	}

	// Store get-roots API call.
	apiCall := apicall.New(ct.GetRootsStr, httpData, getErr)
	log.Printf("%s: %s: writing API Call...", l.URL, logStr)
	if err := st.WriteAPICall(ctx, l, apiCall); err != nil {
		log.Printf("%s: %s: error writing API Call %s: %s", l.URL, logStr, apiCall, err)
	}

	//TODO(RJPercival): Store roots.
}
