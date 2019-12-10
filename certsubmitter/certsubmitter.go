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

// Package certsubmitter periodically issues a certificate or pre-certificate
// and submits it to a CT Log.
package certsubmitter

import (
	"context"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/certgen"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"
)

var logStr = "Certificate Submitter"

// Run runs a Certificate Submitter, which periodically issues a certificate or
// pre-certificate, submits it to a CT Log, and checks and stores the SCT that
// the Log returns.
func Run(ctx context.Context, lc *client.LogClient, ca *certgen.CA, st storage.APICallWriter, l *ctlog.Log, period time.Duration) {
	glog.Infof("%s: %s: started with period %v", l.URL, logStr, period)

	schedule.Every(ctx, period, func(ctx context.Context) {
		glog.Infof("%s: %s: issuing certificate chain...", l.URL, logStr)
		chain, err := ca.IssueCertificateChain()
		if err != nil {
			glog.Errorf("%s: %s: ca.IssueCertificateChain(): %s", l.URL, logStr, err)
			return
		}

		glog.Infof("%s: %s: adding chain...", l.URL, logStr)
		sct, httpData, addErr := lc.AddChain(chain)
		if len(httpData.Body) > 0 {
			glog.Infof("%s: %s: response: %s", l.URL, logStr, httpData.Body)
		}

		// Store get-sth API call.
		apiCall := apicall.New(ct.GetSTHStr, httpData, addErr)
		glog.Infof("%s: %s: writing API Call...", l.URL, logStr)
		if err := st.WriteAPICall(ctx, l, apiCall); err != nil {
			glog.Errorf("%s: %s: error writing API Call %s: %s", l.URL, logStr, apiCall, err)
		}

		if sct == nil {
			return
		}

		// TODO(katjoyce): Check and store SCT
	})

	glog.Infof("%s: %s: stopped", l.URL, logStr)
}
