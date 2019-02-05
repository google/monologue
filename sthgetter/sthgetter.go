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

// Package sthgetter periodically gets an STH from a Log, checks that each one
// meets per-STH requirements defined in RFC 6962, and stores them.
package sthgetter

import (
	"context"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"
)

var logStr = "STH Getter"

// Run runs an STH Getter, which periodically gets an STH from a Log, checks
// that each one meets per-STH requirements defined in RFC 6962, and stores
// them.
func Run(ctx context.Context, lc *client.LogClient, st storage.APICallWriter, l *ctlog.Log, period time.Duration) {
	glog.Infof("%s: %s: started with period %v", l.URL, logStr, period)

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// TODO(katjoyce): Work out when and where to add context timeouts.
			getCheckStoreSTH(ctx, lc, st, l)
		case <-ctx.Done():
			glog.Infof("%s: %s: stopped", l.URL, logStr)
			return
		}
	}
}

func getCheckStoreSTH(ctx context.Context, lc *client.LogClient, st storage.APICallWriter, l *ctlog.Log) {
	// Get STH from Log.
	glog.Infof("%s: %s: getting STH...", l.URL, logStr)
	_, httpData, getErr := lc.GetSTH()
	if getErr != nil {
		glog.Infof("%s: %s: error getting STH: %s", l.URL, logStr, getErr)
	}
	if len(httpData.Body) > 0 {
		glog.Infof("%s: %s: response: %s", l.URL, logStr, httpData.Body)
	}

	// Store get-sth API call.
	apiCall := apicall.New(ct.GetSTHStr, httpData, getErr)
	glog.Infof("%s: %s: writing API Call...", l.URL, logStr)
	if err := st.WriteAPICall(ctx, l, apiCall); err != nil {
		glog.Infof("%s: %s: error writing API Call %s: %s", l.URL, logStr, apiCall, err)
	}

	//TODO(katjoyce): Run checks on the received STH.

	//TODO(katjoyce): Store STH.
}
