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
// Certificate Transparency Log, which can then be used to check that it is
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
	"sync"
	"time"

	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/roots"
	"github.com/google/monologue/schedule"
	"github.com/google/monologue/sth"
	"github.com/google/monologue/storage/print"
)

var (
	rootsGetPeriod = flag.Duration("roots_get_period", 5*time.Minute, "How regularly the monitor should get root certificates from the Log")
	sthGetPeriod   = flag.Duration("sth_get_period", 1*time.Minute, "How regularly the monitor should get an STH from the Log")
	logURL         = flag.String("log_url", "", "The URL of the Log to monitor, e.g. https://ct.googleapis.com/pilot/")
	logName        = flag.String("log_name", "", "A short, snappy, canonical name for the Log to monitor, e.g. google_pilot")
	b64PubKey      = flag.String("public_key", "", "The base64-encoded public key of the Log to monitor")
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

	type Getter struct {
		name   string
		get    func(context.Context, *client.LogClient, *print.Storage, *ctlog.Log) error
		period time.Duration
	}

	getters := []Getter{
		{
			name: "Roots Getter",
			get: func(ctx context.Context, lc *client.LogClient, st *print.Storage, l *ctlog.Log) error {
				_, err := roots.Get(ctx, l, lc, st)
				if err != nil {
					return err
				}
				// TODO(RJPercival): Store roots
				return nil
			},
			period: *rootsGetPeriod,
		},
		{
			name: "STH Getter",
			get: func(ctx context.Context, lc *client.LogClient, st *print.Storage, l *ctlog.Log) error {
				if _, err := sth.Get(ctx, l, lc, st); err != nil {
					return err
				}
				// TODO(katjoyce): Check and store STH
				return nil
			},
			period: *sthGetPeriod,
		},
	}

	var wg sync.WaitGroup
	wg.Add(len(getters))
	for _, g := range getters {
		go func(g Getter) {
			log.Printf("%s: %s: started with period %v", l.URL, g.name, g.period)
			schedule.Every(ctx, g.period, func(ctx context.Context) {
				if err := g.get(ctx, lc, &print.Storage{}, l); err != nil {
					log.Printf("%s: %s: %s", l.URL, g.name, err)
				}
			})
			log.Printf("%s: %s: stopped", l.URL, g.name)
			wg.Done()
		}(g)
	}
	wg.Wait()
}
