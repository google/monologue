// Monitor runs a tool to monitor a single Certificate Transparency Log, to
// check that it is adhering to RFC 6962.
//
// TODO(katjoyce): Once it contains more functionality, turn this into a monitor
// or data collector package so that it can be run on multiple Logs by spinning
// up one per Log.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/google/certificate-transparency-monitor/client"
	"github.com/google/certificate-transparency-monitor/sthgetter"
)

var (
	sthGetPeriod = flag.Duration("sth_get_period", 1*time.Minute, "How regularly the monitor should get an STH from the Log")
	logURL       = flag.String("log_url", "", "The URL of the Log to monitor, e.g. https://ct.googleapis.com/pilot/")
)

func main() {
	flag.Parse()
	if *logURL == "" {
		log.Fatalf("No Log URL provided.")
	}

	ctx := context.Background()

	lc := client.New(*logURL, &http.Client{})
	sthgetter.Run(ctx, lc, *logURL, *sthGetPeriod)
}
