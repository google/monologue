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

// Package storage provides the storage interfaces required by the various
// pieces of the CT monitor.
package storage

import (
	"context"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/monologue/apicall"
	"github.com/google/monologue/ctlog"
)

// APICallWriter is an interface for storing individual calls to CT API
// endpoints.
type APICallWriter interface {
	WriteAPICall(ctx context.Context, l *ctlog.Log, apiCall *apicall.APICall) error
}

// STHWriter is an interface for storing STHs received from a CT Log.
type STHWriter interface {
	WriteSTH(ctx context.Context, l *ctlog.Log, sth *ct.SignedTreeHead, receivedAt time.Time, errs []error) error
}

// RootsWriter is an interface for storing root certificates retrieved from a CT get-roots call.
type RootsWriter interface {
	// WriteRoots stores the fact that the given roots were received from a particular CT Log at the specified time.
	// It will remove any duplicate certificates from roots before storing them.
	WriteRoots(ctx context.Context, l *ctlog.Log, roots []*x509.Certificate, receivedAt time.Time) error
}

// RootSetID uniquely identifies a specific set of certificates, regardless of their order.
type RootSetID string

// RootsReader is an interface for reading root certificates retrieved from an earlier CT get-roots call.
type RootsReader interface {
	// WatchRoots monitors storage for get-roots responses and communicates their content to the caller.
	// A unique, deterministic identifier is generated for any set of root certificates (a RootSetID);
	// this will be sent over the channel and can be used to lookup further information about that set.
	// WatchRoots will immediately send the latest RootSetID when it is first called.
	WatchRoots(ctx context.Context, l *ctlog.Log) (<-chan RootSetID, error)

	// ReadRoots returns the root certificates that make up a particular RootSet,
	// i.e. the set of certificates returned by a CT get-roots call.
	ReadRoots(ctx context.Context, rootSet RootSetID) ([]*x509.Certificate, error)
}
