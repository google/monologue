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
	"fmt"
	"strings"
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
func Run(ctx context.Context, lc *client.LogClient, sv *ct.SignatureVerifier, st storage.APICallWriter, l *ctlog.Log, period time.Duration) {
	glog.Infof("%s: %s: started with period %v", l.URL, logStr, period)

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// TODO(katjoyce): Work out when and where to add context timeouts.
			getCheckStoreSTH(ctx, lc, sv, st, l)
		case <-ctx.Done():
			glog.Infof("%s: %s: stopped", l.URL, logStr)
			return
		}
	}
}

func getCheckStoreSTH(ctx context.Context, lc *client.LogClient, sv *ct.SignatureVerifier, st storage.APICallWriter, l *ctlog.Log) {
	// Get STH from Log.
	glog.Infof("%s: %s: getting STH...", l.URL, logStr)
	sth, httpData, getErr := lc.GetSTH()
	if getErr != nil {
		glog.Errorf("%s: %s: error getting STH: %s", l.URL, logStr, getErr)
	}
	if len(httpData.Body) > 0 {
		glog.Infof("%s: %s: response: %s", l.URL, logStr, httpData.Body)
	}

	// Store get-sth API call.
	apiCall := apicall.New(ct.GetSTHStr, httpData, getErr)
	glog.Infof("%s: %s: writing API Call...", l.URL, logStr)
	if err := st.WriteAPICall(ctx, l, apiCall); err != nil {
		glog.Errorf("%s: %s: error writing API Call %s: %s", l.URL, logStr, apiCall, err)
	}

	if sth == nil {
		return
	}

	// Verify the STH.
	errs := checkSTH(sth, apiCall.End, sv, l)
	if len(errs) != 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "STH verification errors for STH %v:", sth)
		for _, e := range errs {
			fmt.Fprintf(&b, "\n\t%T: %v,", e, e)
		}
		glog.Infof("%s: %s: %s", l.URL, logStr, b.String())
	}

	// TODO(katjoyce): Store STH & errs.
}

func checkSTH(sth *ct.SignedTreeHead, receivedAt time.Time, sv *ct.SignatureVerifier, l *ctlog.Log) []error {
	var errs []error
	// Check that the STH signature verifies.
	glog.Infof("%s: %s: verifying STH signature...", l.URL, logStr)
	if err := sv.VerifySTHSignature(*sth); err != nil {
		errs = append(errs, &SignatureVerificationError{Err: err})
		glog.Warningf("%s: %s: STH signature verification failed", l.URL, logStr)
	}

	// Check STH is not older than the MMD of the Log.
	if err := checkSTHTimestamp(sth, receivedAt, l.MMD); err != nil {
		errs = append(errs, &OldTimestampError{Err: err})
		glog.Warningf("%s: %s: STH timestamp verification failed", l.URL, logStr)
	}

	// TODO(katjoyce): Implement other checks on the STH:
	// - Check that the root hash isn't different from any previously known root
	// hashes for this tree size.
	// - If tree size is 0, Check that the root hash is the SHA-256 hash of the
	// empty string.
	// - Check that the root hash is the right length? Question because client
	// code already checks this when converting ct.GetSTHResponse to
	// ct.SignedTreeHead.

	return errs
}

// checkSTHTimestamp checks that the STH was "no older than the Maximum Merge
// Delay" (RFC 6962 section 3.5) when it was received.
func checkSTHTimestamp(sth *ct.SignedTreeHead, receivedAt time.Time, mmd time.Duration) error {
	sthTimestamp := time.Unix(0, int64(sth.Timestamp*uint64(time.Millisecond)))
	// If the timestamp of the STH is more than the mmd before the time the STH
	// was received, report an error.
	if sthTimestamp.Before(receivedAt.Add(-mmd)) {
		return fmt.Errorf("STH timestamp %v is more than %v before %v", sthTimestamp, mmd, receivedAt)
	}
	return nil
}

// TODO(katjoyce): Work out whether there's any info that should be saved
// separately in these error types.
type SignatureVerificationError struct {
	Err error
}

func (e *SignatureVerificationError) Error() string {
	return e.Err.Error()
}

type OldTimestampError struct {
	Err error
}

func (e *OldTimestampError) Error() string {
	return e.Err.Error()
}
