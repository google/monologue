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
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/logid"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/certgen"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"
)

const logStr = "Certificate Submitter"

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

		// Store add-chain API call.
		apiCall := apicall.New(ct.AddChainStr, httpData, addErr)
		glog.Infof("%s: %s: writing API Call...", l.URL, logStr)
		if err := st.WriteAPICall(ctx, l, apiCall); err != nil {
			glog.Errorf("%s: %s: error writing API Call %s: %s", l.URL, logStr, apiCall, err)
		}

		// Verify the SCT.
		errs := checkSCT(sct, l)

		// Log any errors found.
		if len(errs) != 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "SCT verification errors for SCT %v:", sct)
			for _, e := range errs {
				fmt.Fprintf(&b, "\n\t%T: %v,", e, e)
			}
			glog.Infof("%s: %s: %s", l.URL, logStr, b.String())
		}

		// TODO(katjoyce): Store the SCT & associated errors.
	})

	glog.Infof("%s: %s: stopped", l.URL, logStr)
}

func checkSCT(sct *ct.SignedCertificateTimestamp, l *ctlog.Log) []error {
	var errs []error

	// Check that the SCT is version 1.
	//
	// Section 4.1 of RFC 6962 says ‘a compliant v1 client implementation must
	// not expect this to be v1’, so it would not count as Log misbehaviour if
	// a Log issued an SCT with the version set to something else.  However,
	// given the current state of the CT ecosystem it would be strange to see
	// such a thing, and worth noting if seen.
	//
	// TODO(katjoyce): Add a way to classify errors as 'misbehaviour' vs
	// 'unexpected behaviour worth noting'.
	if sct.SCTVersion != ct.V1 {
		errs = append(errs, &V1Error{Version: sct.SCTVersion})
	}

	// Check that the Log ID is the ID of the Log that the SCT was received
	// from.
	if sct.LogID.KeyID != l.LogID {
		errs = append(errs, &LogIDError{GotID: sct.LogID.KeyID, WantID: l.LogID})
	}

	// TODO(katjoyce): Implement other SCT checks.

	return errs
}

// V1Error indicates that an SCT contained a version that was not v1.
type V1Error struct {
	Version ct.Version
}

func (e *V1Error) Error() string {
	return fmt.Sprintf("version is %v, not v1(0)", e.Version)
}

// LogIDError indicates that an SCT contained the wrong Log ID.
type LogIDError struct {
	GotID  logid.LogID
	WantID logid.LogID
}

func (e *LogIDError) Error() string {
	return fmt.Sprintf("Log ID is %s, want %s", e.GotID, e.WantID)
}
