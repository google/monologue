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

// Package print provides a concrete implementation of the storage interfaces
// needed by the CT monitor, which simply prints everything that is passed to it
// to be 'stored'.
//
// This package is only intended to be a handy tool used during development, and
// will likely be deleted in the not-so-distant future.  Don't rely on it.
package print

import (
	"context"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/ctlog"
)

// Storage implements the storage interfaces needed by the CT monitor.
type Storage struct{}

// WriteAPICall simply prints the API Call passed to it.
func (s *Storage) WriteAPICall(ctx context.Context, l *ctlog.Log, apiCall *apicall.APICall) error {
	glog.Infof("%s: %s", l.Name, apiCall.String())
	return nil
}

// WriteSTH simply prints the STH and errors passed to it.
func (s *Storage) WriteSTH(ctx context.Context, l *ctlog.Log, sth *ct.SignedTreeHead, errs []error) error {
	glog.Infof("%s:\n\tSTH: %s\n\tVerification errors: %s", l.Name, sth, errs)
	return nil
}
