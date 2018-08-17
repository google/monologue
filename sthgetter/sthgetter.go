// Package sthgetter periodically gets an STH from a Log, checks that each one
// meets per-STH requirements defined in RFC 6962, and stores them.
package sthgetter

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/google/certificate-transparency-monitor/client"
)

var logStr = "STH Getter"

// Run runs an STH Getter, which periodically gets an STH from a Log, checks
// that each one meets per-STH requirements defined in RFC 6962, and stores
// them.
func Run(ctx context.Context, lc *client.LogClient, url string, period time.Duration) {
	url = strings.TrimRight(url, "/")
	log.Printf("%s: %s: Started with period %v", url, logStr, period)

	t := time.NewTicker(period)
	for {
		select {
		case <-t.C:
			getCheckStoreSTH(url, lc)
		}
	}
}

func getCheckStoreSTH(url string, lc *client.LogClient) {
	// Get STH from Log.
	log.Printf("%s: %s: getting STH...", url, logStr)
	_, httpData, getErr := lc.GetSTH()
	if getErr != nil {
		log.Printf("%s: %s: error getting STH: %s", url, logStr, getErr)
	}
	if len(httpData.Body) > 0 {
		log.Printf("%s: %s: response: %s", url, logStr, httpData.Body)
	}

	//TODO(katjoyce): Store get-sth API call.

	//TODO(katjoyce): Run checks on the received STH.

	//TODO(katjoyce): Store STH.
}
