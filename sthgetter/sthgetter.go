// Package sthgetter periodically gets an STH from a Log, checks that each one
// meets per-STH requirements defined in RFC 6962, and stores them.
package sthgetter

import (
	"context"
	"log"
	"time"
)

var logStr = "STH Getter"

type STHGetter struct {
	url string
}

func Run(ctx context.Context, url string, period time.Duration) {
	log.Printf("%s: %s: Started with period %v", url, logStr, period)
	sg := &STHGetter{url: url}

	t := time.NewTicker(period)
	for {
		select {
		case <-t.C:
			sg.GetCheckStoreSTH()
		}
	}
}

func (sg *STHGetter) GetCheckStoreSTH() {
	log.Printf("%s: %s: Getting STH...", sg.url, logStr)
	//TODO(katjoyce): Get STH from Log.

	//TODO(katjoyce): Store get-sth API call.

	//TODO(katjoyce): Run checks on the received STH.

	//TODO(katjoyce): Store STH.
}
