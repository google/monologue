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

// Collector runs a tool to collect the data needed to monitor a single
// Certificate Transparency Log, that can then be used to check that it is
// adhering to RFC 6962.
//
// TODO(katjoyce): Once it contains more functionality, turn this into a package
// so that it can be run on multiple Logs by spinning up one per Log.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/google/certificate-transparency-monitor/client"
	"github.com/google/certificate-transparency-monitor/ctlog"
	"github.com/google/certificate-transparency-monitor/sthgetter"
	"github.com/google/certificate-transparency-monitor/storage/print"
)

var (
	sthGetPeriod = flag.Duration("sth_get_period", 1*time.Minute, "How regularly the monitor should get an STH from the Log")
	logURL       = flag.String("log_url", "", "The URL of the Log to monitor, e.g. https://ct.googleapis.com/pilot/")
	logName      = flag.String("log_name", "", "A short, snappy, canonical name for the Log to monitor, e.g. google_pilot")
	b64PubKey    = flag.String("public_key", "", "The base64-encoded public key of the Log to monitor")
)

func main() {
	flag.Parse()
	if *logURL == "" {
		log.Fatalf("No Log URL provided.")
	}
	if *logName == "" {
		log.Fatalf("No Log name provided.")
	}
	if *b64PubKey == "" {
		log.Fatalf("No public key provided.")
	}

	ctx := context.Background()
	l, err := ctlog.New(*logURL, *logName, *b64PubKey)
	if err != nil {
		log.Fatalf("Unable to obtain Log metadata: %s", err)
	}

	lc := client.New(l.URL, &http.Client{})
	sthgetter.Run(ctx, lc, &print.Storage{}, l, *sthGetPeriod)
}
