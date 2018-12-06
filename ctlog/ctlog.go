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

// Package ctlog contains data structures and methods to do with CT Log metadata
// that is needed by Monologue.
//
// TODO(katjoyce): Try to come up with a better package name.
package ctlog

import (
	"crypto"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
)

// Log contains metadata about a CT Log that is needed by Monologue.
type Log struct {
	Name      string
	URL       string
	PublicKey crypto.PublicKey
}

// New creates a Log structure, populating the fields appropriately.
//
// TODO(katjoyce): replace this implementation with something less hacky that
// takes log details from a log list struct based on the new Log list JSON
// schema.
func New(url, name, b64PubKey string) (*Log, error) {
	pk, err := ct.PublicKeyFromB64(b64PubKey)
	if err != nil {
		return nil, fmt.Errorf("ct.PublicKeyFromB64(): %s", err)
	}
	return &Log{
		Name:      name,
		URL:       url,
		PublicKey: pk,
	}, nil
}
