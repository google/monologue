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

package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"

	_ "github.com/go-sql-driver/mysql" // Load MySQL driver
)

type entry struct {
	BaseURL, Summary, Category string, IsViolation bool, FullURL, Details string
}

func checkContents(ctx context.Context, t *testing.T, want []entry) {
	t.Helper()

	tx, err := testDB.BeginTx(ctx, nil /* opts */)
	if err != nil {
		t.Fatalf("failed to create transaction: %v", err)
	}
	defer tx.Commit()
	rows, err := tx.QueryContext(ctx, "SELECT BaseURL, Summary, Category, FullURL, Details FROM Incidents;")
	if err != nil {
		t.Fatalf("failed to query rows: %v", err)
	}
	defer rows.Close()

	var got []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.BaseURL, &e.Summary, &e.Category, &e.FullURL, &e.Details); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}
		got = append(got, e)
	}
	if err := rows.Err(); err != nil {
		t.Errorf("incident table iteration failed: %v", err)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("incident table: diff (-got +want)\n%s", diff)
	}
}

func TestLogf(t *testing.T) {
	ctx := context.Background()
	cleanTestDB(ctx)

	checkContents(ctx, t, nil)

	reporter, err := NewMySQLReporter(ctx, testDB, "unittest")
	if err != nil {
		t.Fatalf("failed to build MySQLReporter: %v", err)
	}
	e := entry{BaseURL: "base", Summary: "summary", Category: "signature", IsViolation: false, FullURL: "full", Details: "blah"}
	ev := entry{BaseURL: "base", Summary: "summary", Category: "signature", IssViolation: true, FullURL: "full", Details: "blah"}

	reporter.LogViolation(ctx, e.BaseURL, e.Summary, e.Category, e.FullURL, e.Details)
	checkContents(ctx, t, []entry{ev})

	reporter.LogUpdate(ctx, e.BaseURL, e.Summary, e.Category, e.FullURL, e.Details)
	checkContents(ctx, t, []entry{ev, e})

	reporter.LogViolationf(ctx, e.BaseURL, e.Summary, e.Category, e.FullURL, "%s", e.Details)
	checkContents(ctx, t, []entry{ev, e, ev})
}

func TestMain(m *testing.M) {
	flag.Parse()
	if err := mySQLAvailable(); err != nil {
		glog.Errorf("MySQL not available, skipping all MySQL storage tests: %v", err)
		return
	}
	ctx := context.Background()
	var err error
	testDB, err = newIncidentDB(ctx)
	if err != nil {
		glog.Exitf("failed to create test database: %v", err)
	}
	defer testDB.Close()
	cleanTestDB(ctx)
	ec := m.Run()
	os.Exit(ec)
}

var (
	testDB      *sql.DB
	dataSource  = "root@tcp(127.0.0.1)/"
	incidentSQL = "incident.sql"
)

// mySQLAvailable indicates whether a default MySQL database is available.
func mySQLAvailable() error {
	db, err := sql.Open("mysql", dataSource)
	if err != nil {
		return fmt.Errorf("sql.Open(): %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("db.Ping(): %v", err)
	}
	return nil
}

// newEmptyDB creates a new, empty database.
func newEmptyDB(ctx context.Context) (*sql.DB, error) {
	db, err := sql.Open("mysql", dataSource)
	if err != nil {
		return nil, err
	}

	// Create a randomly-named database and then connect using the new name.
	name := fmt.Sprintf("mono_%v", time.Now().UnixNano())

	stmt := fmt.Sprintf("CREATE DATABASE %v", name)
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return nil, fmt.Errorf("error running statement %q: %v", stmt, err)
	}
	db.Close()

	db, err = sql.Open("mysql", dataSource+name)
	if err != nil {
		return nil, fmt.Errorf("failed to open new database %q: %v", name, err)
	}
	return db, db.Ping()
}

// newIncidentDB creates an empty database with the incident schema.
func newIncidentDB(ctx context.Context) (*sql.DB, error) {
	db, err := newEmptyDB(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty DB: %v", err)
	}

	sqlBytes, err := ioutil.ReadFile(incidentSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema SQL: %v", err)
	}

	for _, stmt := range strings.Split(sanitize(string(sqlBytes)), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("error running statement %q: %v", stmt, err)
		}
	}
	return db, nil
}

func sanitize(script string) string {
	buf := &bytes.Buffer{}
	for _, line := range strings.Split(string(script), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || strings.Index(line, "--") == 0 {
			continue // skip empty lines and comments
		}
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	return buf.String()
}

func cleanTestDB(ctx context.Context) {
	if _, err := testDB.ExecContext(ctx, fmt.Sprintf("DELETE FROM Incidents")); err != nil {
		glog.Exitf("Failed to delete rows in Incidents: %v", err)
	}
}
