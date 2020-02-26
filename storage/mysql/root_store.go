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

// Package mysql provides a MySQL based implementation of Monologue storage.
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/rootsanalyzer"
	"github.com/google/monologue/storage"
)

// RootStore implements storage.RootsWriter interface.
type rootStore struct {
	rootDB *sql.DB
}

// NewRootStore builds an RootStore instance that records root certificates in a MySQL database.
func NewRootStore(ctx context.Context, db *sql.DB) storage.RootsWriter {
	return &rootStore{rootDB: db}
}

func (rs *rootStore) WriteRoots(ctx context.Context, l *ctlog.Log, roots []*x509.Certificate, receivedAt time.Time) error {
	rootSetID, err := rootsanalyzer.GenerateSetID(roots)
	if err != nil {
		return fmt.Errorf("unable to generate RootSetID: %s", err)
	}
	rootSetIDBytes := []byte(rootSetID)

	for _, r := range roots {
		rootID, err := rootsanalyzer.GenerateCertID(r)
		if err != nil {
			return fmt.Errorf("WriteRoots: %s", err)
		}

		if _, err = rs.rootDB.ExecContext(ctx, "INSERT INTO Roots(ID, DER) VALUES (?, ?) ON DUPLICATE KEY UPDATE ID=ID;", rootID[:], r.Raw); err != nil {
			return fmt.Errorf("WriteRoots: %s", err)
		}

		if _, err = rs.rootDB.ExecContext(ctx, "INSERT INTO RootSets(RootSetID, RootID) VALUES (?, ?) ON DUPLICATE KEY UPDATE RootSetID=RootSetID;", rootSetIDBytes, rootID[:]); err != nil {
			return fmt.Errorf("WriteRoots: %s", err)
		}
	}

	if _, err = rs.rootDB.ExecContext(ctx, "INSERT INTO RootSetObservations(LogName, RootSetID, ReceivedAt) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE RootSetID=RootSetID;", l.Name, rootSetIDBytes, receivedAt); err != nil {
		return fmt.Errorf("WriteRoots: %s", err)
	}

	return nil
}
