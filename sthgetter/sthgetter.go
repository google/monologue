// Package sthgetter periodically gets an STH from a Log, checks that each one
// meets per-STH requirements defined in RFC 6962, and stores them.
package sthgetter

import (
	"context"
	"fmt"
	"log"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-monitor/client"
	"github.com/google/certificate-transparency-monitor/monitor"
	"github.com/google/certificate-transparency-monitor/storage"
)

var logStr = "STH Getter"

// Run runs an STH Getter, which periodically gets an STH from a Log, checks
// that each one meets per-STH requirements defined in RFC 6962, and stores
// them.
func Run(ctx context.Context, lc *client.LogClient, sv *ct.SignatureVerifier, st storage.APICallWriter, url string, period time.Duration) {
	log.Printf("%s: %s: started with period %v", url, logStr, period)

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// TODO(katjoyce): Work out when and where to add context timeouts.
			getCheckStoreSTH(ctx, url, lc, sv, st)
		case <-ctx.Done():
			log.Printf("%s: %s: stopped", url, logStr)
			return
		}
	}
}

func getCheckStoreSTH(ctx context.Context, url string, lc *client.LogClient, sv *ct.SignatureVerifier, st storage.APICallWriter) {
	// Get STH from Log.
	log.Printf("%s: %s: getting STH...", url, logStr)
	sth, httpData, getErr := lc.GetSTH()
	if getErr != nil {
		log.Printf("%s: %s: error getting STH: %s", url, logStr, getErr)
	}
	if len(httpData.Body) > 0 {
		log.Printf("%s: %s: response: %s", url, logStr, httpData.Body)
	}

	// Store get-sth API call.
	apiCall := monitor.CreateAPICall(ct.GetSTHStr, httpData, getErr)
	log.Printf("%s: %s: writing API Call...", url, logStr)
	if err := st.WriteAPICall(ctx, apiCall); err != nil {
		log.Printf("%s: %s: error writing API Call %s: %s", url, logStr, apiCall, err)
	}

	if sth == nil {
		return
	}

	//TODO(katjoyce): Run checks on the received STH.
	// Check that the STH signature verifies.
	log.Printf("%s: %s: verifying signature...", url, logStr)
	var verificationErr error
	if err := sv.VerifySTHSignature(*sth); err != nil {
		verificationErr = &SignatureVerificationError{Err: err}
	}
	fmt.Println(verificationErr)

	//TODO(katjoyce): Store STH.
}

type SignatureVerificationError struct {
	Err error
}

func (e *SignatureVerificationError) Error() string {
	return e.Err.Error()
}
