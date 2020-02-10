// Copyright 2020 Google LLC
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

package storage

import (
	"github.com/google/certificate-transparency-go/x509"
)

// RootSetID uniquely identifies a specific set of certificates, regardless of their order.
type RootSetID string

// IDMaker is interface for generating IDs for sets of root-certificates.
type IDMaker interface {
	GenerateSetID(roots []*x509.Certificate) (RootSetID, error)
}
