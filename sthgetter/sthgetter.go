// Package sthgetter periodically gets an STH from a Log, checks that each one
// meets per-STH requirements defined in RFC 6962, and stores them.
package sthgetter

import (
	"context"
	"log"
	"time"

	"github.com/google/certificate-transparency-monitor/client"
)

var logStr = "STH Getter"

type STHGetter struct {
	url       string
	logClient *client.LogClient
}

func Run(ctx context.Context, lc *client.LogClient, url string, period time.Duration) {
	log.Printf("%s: %s: Started with period %v", url, logStr, period)
	sg := &STHGetter{url: url, logClient: lc}

	t := time.NewTicker(period)
	for {
		select {
		case <-t.C:
			sg.GetCheckStoreSTH()
		}
	}
}

func (sg *STHGetter) GetCheckStoreSTH() {
	// Get STH from Log.
	log.Printf("%s: %s: getting STH...", sg.url, logStr)
	_, httpData, getErr := sg.logClient.GetSTH()
	if getErr != nil {
		log.Printf("%s: %s: error getting STH: %s", sg.url, logStr, getErr)
	}
	if len(httpData.Body) > 0 {
		log.Printf("%s: %s: response: %s", sg.url, logStr, httpData.Body)
	}

	//TODO(katjoyce): Store get-sth API call.

	//TODO(katjoyce): Run checks on the received STH.

	//TODO(katjoyce): Store STH.
}
