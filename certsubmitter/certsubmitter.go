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
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/logid"
	"github.com/google/certificate-transparency-go/schedule"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/certgen"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/errors"
	"github.com/google/monologue/storage"
)

const logStr = "Certificate Submitter"

// Run runs a Certificate Submitter, which periodically issues a certificate or
// pre-certificate, submits it to a CT Log, and checks and stores the SCT that
// the Log returns.
func Run(ctx context.Context, lc *client.LogClient, ca *certgen.CA, sv *ct.SignatureVerifier, st storage.APICallWriter, l *ctlog.Log, period time.Duration) {
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
		errs := checkSCT(sct, chain, sv, l)

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

func checkSCT(sct *ct.SignedCertificateTimestamp, chain []*x509.Certificate, sv *ct.SignatureVerifier, l *ctlog.Log) []error {
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
		errs = append(errs, &SCTVersionError{Got: sct.SCTVersion, Want: ct.V1})
	}

	// Check that the Log ID is the ID of the Log that the SCT was received
	// from.
	if sct.LogID.KeyID != l.LogID {
		errs = append(errs, &SCTLogIDError{Got: sct.LogID.KeyID, Want: l.LogID})
	}

	// Check that Extensions in the SCT is empty.
	//
	// Section 3.2 of RFC 6962 says '"extensions" are future extensions to this
	// protocol version (v1)', but then goes on to say 'Currently, no extensions
	// are specified' and Section 4.1 says 'Logs should set this to the empty
	// string'. This is another case where having data in this field may not
	// count as misbehaviour, but may be note worthy if seen.
	if sct.Extensions != nil && !bytes.Equal(sct.Extensions, []byte{}) {
		errs = append(errs, &SCTExtensionsError{Extensions: sct.Extensions})
	}

	// Verify the signature of the SCT.
	if err := ctutil.VerifySCTWithVerifier(sv, chain, sct, false); err != nil {
		errs = append(errs, &errors.SignatureVerificationError{Err: err})
	}

	// TODO(katjoyce): Implement other SCT checks.

	return errs
}

// SCTVersionError indicates that an SCT contained a version that was not as
// expected.
type SCTVersionError struct {
	Got  ct.Version
	Want ct.Version
}

func (e *SCTVersionError) Error() string {
	return fmt.Sprintf("version is %v, want %v", e.Got, e.Want)
}

// SCTLogIDError indicates that an SCT contained the wrong Log ID.
type SCTLogIDError struct {
	Got  logid.LogID
	Want logid.LogID
}

func (e *SCTLogIDError) Error() string {
	return fmt.Sprintf("Log ID is %s, want %s", e.Got, e.Want)
}

// SCTExtensionsError indicates that an SCT contained unexpected data in its
// extensions field.
type SCTExtensionsError struct {
	Extensions ct.CTExtensions
}

func (e *SCTExtensionsError) Error() string {
	return fmt.Sprintf("unexpected extensions data: %v", e.Extensions)
}
