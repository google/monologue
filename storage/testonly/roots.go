// Copyright 2019 Google LLC
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

// Package testonly contains fakes for use in tests that interact with storage.
package testonly

import (
	"context"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage"
)

// FakeRootsReader returns preset values in order to fulfill the storage.RootsReader interface.
type FakeRootsReader struct {
	// RootSetChan is returned by WatchRoots.
	RootSetChan chan storage.RootSetID
	// RootCerts maps RootSetIDs to sets of certificates. It is used by ReadRoots.
	RootSetCerts map[storage.RootSetID][]*x509.Certificate
}

// WatchRoots returns FakeRootsReader.RootSetChan.
func (f *FakeRootsReader) WatchRoots(ctx context.Context, l *ctlog.Log) (<-chan storage.RootSetID, error) {
	return f.RootSetChan, nil
}

// ReadRoots returns FakeRootsReader.RootSetCerts[rootSet].
func (f *FakeRootsReader) ReadRoots(ctx context.Context, rootSet storage.RootSetID) ([]*x509.Certificate, error) {
	return f.RootSetCerts[rootSet], nil
}
