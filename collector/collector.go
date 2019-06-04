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

// Package collector runs a tool to collect the data needed to monitor a single
// Certificate Transparency Log, which can then be used to check that it is
// adhering to RFC 6962.
package collector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/rootsgetter"
	"github.com/google/monologue/sthgetter"
	"github.com/google/monologue/storage"
)

// Config contains all of the configuration details for running the collector
// for a particular Log.
type Config struct {
	// Details of the Log to collect data from.
	Log *ctlog.Log
	// How regularly the monitor should get an STH from the Log.
	// To disable STH-getting, set to 0.
	STHGetPeriod time.Duration
	// How regularly the monitor should get root certificates from the Log.
	// To disable roots-getting, set to 0.
	RootsGetPeriod time.Duration
}

// Storage is an interface containing all of the storage methods required by
// Monologue.  It will therefore satisfy every interface needed by the various
// modules that the collector runs (e.g. sthgetter, rootsgetter etc).
type Storage interface {
	storage.APICallWriter
	storage.STHWriter
}

// Run runs the collector on the Log specified in cfg, and stores the collected
// data in st.
func Run(ctx context.Context, cfg *Config, cl *http.Client, st Storage) error {
	if cfg == nil {
		return errors.New("nil Config")
	}
	if cfg.Log == nil {
		return errors.New("no Log provided in Config")
	}

	lc := client.New(cfg.Log.URL, cl)

	sv, err := ct.NewSignatureVerifier(cfg.Log.PublicKey)
	if err != nil {
		return fmt.Errorf("couldn't create signature verifier: %s", err)
	}

	var wg sync.WaitGroup
	if cfg.STHGetPeriod > 0 {
		wg.Add(1)
		go func() {
			sthgetter.Run(ctx, lc, sv, st, cfg.Log, cfg.STHGetPeriod)
			wg.Done()
		}()
	}
	if cfg.RootsGetPeriod > 0 {
		wg.Add(1)
		go func() {
			rootsgetter.Run(ctx, lc, st, cfg.Log, cfg.RootsGetPeriod)
			wg.Done()
		}()
	}
	wg.Wait()

	return nil
}
