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

// Package mysql provides a MySQL based implementation of incident management.
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/google/monologue/incident"
)

type mysqlReporter struct {
	db     *sql.DB
	stmt   *sql.Stmt
	source string
}

// NewMySQLReporter builds an incident.Reporter instance that records incidents
// in a MySQL database, all of which will be marked as emanating from the given
// source.
func NewMySQLReporter(ctx context.Context, db *sql.DB, source string) (incident.Reporter, error) {
	stmt, err := db.PrepareContext(ctx, "INSERT INTO Incidents(Timestamp, Source, BaseURL, Summary, Category, IsViolation, FullURL, Details) VALUES (?, ?, ?, ?, ?, ?, ?);")
	if err != nil {
		return nil, fmt.Errorf("failed to prepare context for %q: %v", source, err)
	}
	return &mysqlReporter{db: db, source: source, stmt: stmt}, nil
}

// Log records an incident with the given details.
func (m *mysqlReporter) Log(ctx context.Context, baseURL, summary, category string, isViolation bool, fullURL, details string) {
	now := time.Now()
	glog.Errorf("[%s] %s: %s (category=%s url=%s)\n  %s", now, baseURL, summary, category, isViolation, fullURL, details)
	if _, err := m.stmt.ExecContext(ctx, now, m.source, baseURL, summary, category, isViolation, fullURL, details); err != nil {
		glog.Errorf("failed to insert incident for %q: %v", m.source, err)
	}
}

// Logf records an incident with the given details and formatting.
func (m *mysqlReporter) Logf(ctx context.Context, baseURL, summary, category string, isViolation bool, fullURL, detailsFmt string, args ...interface{}) {
	details := fmt.Sprintf(detailsFmt, args...)
	m.Log(ctx, baseURL, summary, category, isViolation, fullURL, details)
}
