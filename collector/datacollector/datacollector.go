// Datacollector runs a tool to collect the data needed to monitor Certificate
// Transparency Logs, which can then be used to check that they are adhering to
//RFC 6962.
package main

import (
	"context"
	"flag"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/google/monologue/collector"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage/print"
)

var (
	rootsGetPeriod = flag.Duration("roots_get_period", 0, "How regularly the monitor should get root certificates from the Log")
	sthGetPeriod   = flag.Duration("sth_get_period", 0, "How regularly the monitor should get an STH from the Log")
	// TODO(katjoyce): Change to read from log_list.json or all_logs_list.json to get Log details.
	// TODO(katjoyce): Add ability to run against multiple Logs.
	logURL    = flag.String("log_url", "", "The URL of the Log to monitor, e.g. https://ct.googleapis.com/pilot/")
	logName   = flag.String("log_name", "", "A short, snappy, canonical name for the Log to monitor, e.g. google_pilot")
	b64PubKey = flag.String("public_key", "", "The base64-encoded public key of the Log to monitor")
	mmd       = flag.Duration("mmd", 24*time.Hour, "The Maximum Merge Delay for the Log")
)

func main() {
	flag.Parse()
	if *logURL == "" {
		glog.Exitf("No Log URL provided.")
	}
	if *logName == "" {
		glog.Exitf("No Log name provided.")
	}
	if *b64PubKey == "" {
		glog.Exitf("No public key provided.")
	}

	ctx := context.Background()
	l, err := ctlog.New(*logURL, *logName, *b64PubKey, *mmd)
	if err != nil {
		glog.Exitf("Unable to obtain Log metadata: %s", err)
	}

	cfg := &collector.Config{
		Log:            l,
		STHGetPeriod:   *sthGetPeriod,
		RootsGetPeriod: *rootsGetPeriod,
	}

	collector.Run(ctx, cfg, &http.Client{}, &print.Storage{})
}
