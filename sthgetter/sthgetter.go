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

// Package sthgetter periodically gets an STH from a Log, checks that each one
// meets per-STH requirements defined in RFC 6962, and stores them.
package sthgetter

import (
	"context"
	"fmt"
	"log"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/client"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"
)

const logStr = "STH Getter"

// GetSTH fetches the latest Signed Tree Head from a Log, using the given client.
// Records details of the get-sth API call to the provided storage.
func GetSTH(ctx context.Context, l *ctlog.Log, lc *client.LogClient, store storage.APICallWriter) (*ct.SignedTreeHead, error) {
	log.Printf("%s: %s: getting STH...", l.URL, logStr)
	sth, httpData, getErr := lc.GetSTH()

	log.Printf("%s: %s: writing get-sth API Call...", l.URL, logStr)
	apiCall := apicall.New(ct.GetSTHStr, httpData, getErr)
	if err := store.WriteAPICall(ctx, l, apiCall); err != nil {
		return nil, fmt.Errorf("error writing API Call %s: %s", apiCall, err)
	}

	if getErr != nil {
		return nil, fmt.Errorf("error getting STH: %s", getErr)
	}

	if len(httpData.Body) > 0 {
		log.Printf("%s: %s: response: %s", l.URL, logStr, httpData.Body)
	}

	return sth, nil
}

// CheckSTH checks that the Signed Tree Head from a Log is valid.
// TODO(katjoyce): Implement CheckSTH.
func CheckSTH(ctx context.Context, log *ctlog.Log, sth *ct.SignedTreeHead) error {
	return fmt.Errorf("not implemented")
}
