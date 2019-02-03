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

// Package roots provides functions for fetching and handling root certificates from Certificate Transparency Logs.
package roots

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"
)

// Get fetches the current root certificates trusted by a Log, using the given client.
// Records details of the get-roots API call to the provided storage.
func Get(ctx context.Context, l *ctlog.Log, lc *client.LogClient, st storage.APICallWriter) ([]*x509.Certificate, error) {
	log.Printf("%s: getting roots...", l.URL)
	roots, httpData, getErr := lc.GetRoots()

	log.Printf("%s: writing get-roots API Call...", l.URL)
	apiCall := apicall.New(ct.GetRootsStr, httpData, getErr)
	if err := st.WriteAPICall(ctx, l, apiCall); err != nil {
		return nil, fmt.Errorf("error writing API Call %s: %s", apiCall, err)
	}

	if getErr != nil {
		return nil, fmt.Errorf("error getting roots: %s", getErr)
	}

	log.Printf("%s: get-roots response: %d certificates", l.URL, len(roots))
	return roots, nil
}
