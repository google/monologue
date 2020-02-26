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

package mysql

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-cmp/cmp"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage/mysql/testdb"

	_ "github.com/go-sql-driver/mysql" // Load MySQL driver
)

func mustCreateNewLog(url, name, b64PubKey string) *ctlog.Log {
	l, err := ctlog.New(url, name, b64PubKey, 24*time.Hour, nil)
	if err != nil {
		glog.Fatalf("ctlog.New(%q, %q, %q) = _, %s", url, name, b64PubKey, err)
	}
	return l
}

var (
	pilot = mustCreateNewLog("https://ct.googleapis.com/pilot", "pilot", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==")
)

func mustParseCert(b64CertDER string, t *testing.T) *x509.Certificate {
	t.Helper()
	certDER, err := base64.StdEncoding.DecodeString(b64CertDER)
	if err != nil {
		t.Fatalf("Unexpected error while preparing testdata: %s", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Unexpected error while preparing testdata: %s", err)
	}
	return cert
}

func mustBytes32(in []byte, t *testing.T) [32]byte {
	t.Helper()
	if len(in) != 32 {
		t.Fatalf("mustBytes32 expects input of length 32, got %d", len(in))
	}
	var out [32]byte
	copy(out[:], in)
	return out
}

func mustHexCode32(s string, t *testing.T) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Unexpected error while preparing testdata: %s", err)
	}
	return mustBytes32(decoded, t)
}

type rootEntry struct {
	RootID    []byte
	SHA256DER []byte
}

type setEntry struct {
	RootSetID []byte
	RootID    []byte
}

type obEntry struct {
	LogName    string
	RootSetID  []byte
	ReceivedAt time.Time
}

func checkContents(ctx context.Context, t *testing.T, want []rootEntry, wantSets []setEntry, wantObservations []obEntry) {
	t.Helper()

	tx, err := testDB.BeginTx(ctx, nil /* opts */)
	if err != nil {
		t.Fatalf("failed to create transaction: %v", err)
	}
	defer tx.Commit()

	// Roots
	rows, err := tx.QueryContext(ctx, "SELECT ID, DER FROM Roots")
	if err != nil {
		t.Fatalf("failed to query rows: %v", err)
	}
	defer rows.Close()

	var got []rootEntry
	for rows.Next() {
		var e rootEntry
		if err := rows.Scan(&e.RootID, &e.SHA256DER); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}
		got = append(got, e)
	}
	if err := rows.Err(); err != nil {
		t.Errorf("root table iteration failed: %v", err)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("root table: diff (-got +want)\n%s", diff)
	}

	// RootSets
	setrows, err := tx.QueryContext(ctx, "SELECT RootSetID, RootID FROM RootSets;")
	if err != nil {
		t.Fatalf("failed to query rows: %v", err)
	}
	defer setrows.Close()

	var gotS []setEntry
	for setrows.Next() {
		var e setEntry
		if err := setrows.Scan(&e.RootSetID, &e.RootID); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}
		gotS = append(gotS, e)
	}
	if err := rows.Err(); err != nil {
		t.Errorf("rootset table iteration failed: %v", err)
	}
	if diff := cmp.Diff(gotS, wantSets); diff != "" {
		t.Errorf("rootset table: diff (-got +want)\n%s", diff)
	}

	// RootSetObservations
	obrows, err := tx.QueryContext(ctx, "SELECT LogName, RootSetID, ReceivedAt FROM RootSetObservations;")
	if err != nil {
		t.Fatalf("failed to query rows: %v", err)
	}
	defer obrows.Close()

	var gotO []obEntry
	for obrows.Next() {
		var e obEntry
		if err := obrows.Scan(&e.LogName, &e.RootSetID, &e.ReceivedAt); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}
		gotO = append(gotO, e)
	}
	if err := obrows.Err(); err != nil {
		t.Errorf("RootSetObservations table iteration failed: %v", err)
	}
	if diff := cmp.Diff(gotO, wantObservations); diff != "" {
		t.Errorf("RootSetObservations table: diff (-got +want)\n%s", diff)
	}
}

func TestWriteRoots(t *testing.T) {
	root1 := mustParseCert("MIIFzTCCA7WgAwIBAgIJAJ7TzLHRLKJyMA0GCSqGSIb3DQEBBQUAMH0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xFzAVBgNVBAoMDkdvb2dsZSBVSyBMdGQuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kxITAfBgNVBAMMGE1lcmdlIERlbGF5IE1vbml0b3IgUm9vdDAeFw0xNDA3MTcxMjA1NDNaFw00MTEyMDIxMjA1NDNaMH0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xFzAVBgNVBAoMDkdvb2dsZSBVSyBMdGQuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kxITAfBgNVBAMMGE1lcmdlIERlbGF5IE1vbml0b3IgUm9vdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKoWHPIgXtgaxWVIPNpCaj2y5Yj9t1ixe5PqjWhJXVNKAbpPbNHA/AoSivecBm3FTD9DfgW6J17mHb+cvbKSgYNzgTk5e2GJrnOP7yubYJpt2OCw0OILJD25NsApzcIiCvLA4aXkqkGgBq9FiVfisReNJxVu8MtxfhbVQCXZf0PpkW+yQPuF99V5Ri+grHbHYlaEN1C/HM3+t2yMR4hkd2RNXsMjViit9qCchIi/pQNt5xeQgVGmtYXyc92ftTMrmvduj7+pHq9DEYFt3ifFxE8v0GzCIE1xR/d7prFqKl/KRwAjYUcpU4vuazywcmRxODKuwWFVDrUBkGgCIVIjrMJWStH5i7WTSSTrVtOD/HWYvkXInZlSgcDvsNIG0pptJaEKSP4jUzI3nFymnoNZn6pnfdIII/XISpYSVeyl1IcdVMod8HdKoRew9CzW6f2n6KSKU5I8X5QEM1NUTmRLWmVi5c75/CvS/PzOMyMzXPf+fE2Dwbf4OcR5AZLTupqp8yCTqo7ny+cIBZ1TjcZjzKG4JTMaqDZ1Sg0T3mO/ZbbiBE3N8EHxoMWpw8OP50z1dtRRwj6qUZ2zLvngOb2EihlMO15BpVZC3Cg929c9Hdl65pUd4YrYnQBQB/rn6IvHo8zot8zElgOg22fHbViijUt3qnRggB40N30MXkYGwuJbAgMBAAGjUDBOMB0GA1UdDgQWBBTzX3t1SeN4QTlqILZ8a0xcyT1YQTAfBgNVHSMEGDAWgBTzX3t1SeN4QTlqILZ8a0xcyT1YQTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4ICAQB3HP6jRXmpdSDYwkI9aOzQeJH4x/HDi/PNMOqdNje/xdNzUy7HZWVYvvSVBkZ1DG/ghcUtn/wJ5m6/orBn3ncnyzgdKyXbWLnCGX/V61PgIPQpuGo7HzegenYaZqWz7NeXxGaVo3/y1HxUEmvmvSiioQM1cifGtz9/aJsJtIkn5umlImenKKEV1Ly7R3Uz3Cjz/Ffac1o+xU+8NpkLF/67fkazJCCMH6dCWgy6SL3AOB6oKFIVJhw8SD8vptHaDbpJSRBxifMtcop/85XUNDCvO4zkvlB1vPZ9ZmYZQdyL43NA+PkoKy0qrdaQZZMq1Jdp+Lx/yeX255/zkkILp43jFyd44rZ+TfGEQN1WHlp4RMjvoGwOX1uGlfoGkRSgBRj7TBn514VYMbXu687RS4WY2v+kny3PUFv/ZBfYSyjoNZnU4Dce9kstgv+gaKMQRPcyL+4vZU7DV8nBIfNFilCXKMN/VnNBKtDV52qmtOsVghgai+QE09w15x7dg+44gIfWFHxNhvHKys+s4BBN8fSxAMLOsb5NGFHE8x58RAkmIYWHjyPM6zB5AUPw1b2A0sDtQmCqoxJZfZUKrzyLz8gS2aVujRYN13KklHQ3EKfkeKBG2KXVBe5rjMN/7Anf1MtXxsTY6O8qIuHZ5QlXhSYzE41yIlPlG6d7AGnTiBIgeg==", t)
	root1ID := mustHexCode32("86d8219c7e2b6009e37eb14356268489b81379e076e8f372e3dde8c162a34134", t)
	root2 := mustParseCert("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", t)
	root2ID := mustHexCode32("0ac607a81e0828b60dc88034cccafd982cddf95b3a0efd1f8cd59232e5fb754f", t)

	aprilTimestamp := time.Date(2019, time.April, 10, 15, 0, 0, 0, time.UTC)
	mayTimestamp := time.Date(2019, time.May, 10, 15, 0, 0, 0, time.UTC)
	juneTimestamp := time.Date(2019, time.June, 10, 15, 0, 0, 0, time.UTC)

	// ID for a set of only root1
	root1SetID := mustHexCode32("35d1cd6dbd84a37a5884351d1d0d197d2e9048709b1442391cdfac69f8371272", t)
	root1AndRoot2SetID := mustHexCode32("be6b3e0736f965cf707eb773709027a7250de5e32910f09370146d1318d6df04", t)

	e := rootEntry{RootID: root1ID[:], SHA256DER: root1.Raw}
	e2 := rootEntry{RootID: root2ID[:], SHA256DER: root2.Raw}

	s := setEntry{RootSetID: root1SetID[:], RootID: root1ID[:]}
	s1 := setEntry{RootSetID: root1AndRoot2SetID[:], RootID: root1ID[:]}
	s2 := setEntry{RootSetID: root1AndRoot2SetID[:], RootID: root2ID[:]}

	o := obEntry{LogName: "pilot", RootSetID: root1SetID[:], ReceivedAt: aprilTimestamp}
	oMay := obEntry{LogName: "pilot", RootSetID: root1SetID[:], ReceivedAt: mayTimestamp}
	o2May := obEntry{LogName: "pilot", RootSetID: root1AndRoot2SetID[:], ReceivedAt: mayTimestamp}
	o2June := obEntry{LogName: "pilot", RootSetID: root1AndRoot2SetID[:], ReceivedAt: juneTimestamp}

	type rootData struct {
		roots      []*x509.Certificate
		receivedAt time.Time
	}

	tests := []struct {
		name             string
		log              *ctlog.Log
		rootsData        []rootData
		wantErr          bool
		wantRoots        []rootEntry
		wantSets         []setEntry
		wantObservations []obEntry
	}{
		{
			name: "one root",
			log:  pilot,
			rootsData: []rootData{
				{
					roots: []*x509.Certificate{
						root1,
					},
					receivedAt: aprilTimestamp,
				},
			},
			wantRoots:        []rootEntry{e},
			wantSets:         []setEntry{s},
			wantObservations: []obEntry{o},
		},
		{
			name: "duplicated root",
			log:  pilot,
			rootsData: []rootData{
				{
					roots: []*x509.Certificate{
						root1,
					},
					receivedAt: aprilTimestamp,
				},
				{
					roots: []*x509.Certificate{
						root1,
					},
					receivedAt: mayTimestamp,
				},
			},
			wantRoots:        []rootEntry{e},
			wantSets:         []setEntry{s},
			wantObservations: []obEntry{o, oMay},
		},
		{
			name: "root order",
			log:  pilot,
			rootsData: []rootData{
				{
					roots: []*x509.Certificate{
						root1,
					},
					receivedAt: aprilTimestamp,
				},
				{
					roots: []*x509.Certificate{
						root1, root2,
					},
					receivedAt: mayTimestamp,
				},
				{
					roots: []*x509.Certificate{
						root2, root1,
					},
					receivedAt: juneTimestamp,
				},
			},
			wantRoots:        []rootEntry{e2, e},
			wantSets:         []setEntry{s, s2, s1},
			wantObservations: []obEntry{o, o2May, o2June},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			testdb.Clean(ctx, testDB, "Roots")
			testdb.Clean(ctx, testDB, "RootSets")
			testdb.Clean(ctx, testDB, "RootSetObservations")
			checkContents(ctx, t, nil, nil, nil)
			st := NewRootStore(ctx, testDB)

			var gotErr bool
			for _, rdt := range test.rootsData {
				if err := st.WriteRoots(ctx, test.log, rdt.roots, rdt.receivedAt); err != nil {
					if !test.wantErr {
						t.Fatalf("Storage.WriteRoots(ctx, %v, %v, %v) = %s, want nil", test.log, rdt.roots, rdt.receivedAt, err)
					}
					gotErr = true
				}
			}
			if !gotErr && test.wantErr {
				t.Fatal("Storage.WriteRoots() for all Root-sets produced no errors, wanted error")
			}
			checkContents(ctx, t, test.wantRoots, test.wantSets, test.wantObservations)
		})
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	if err := testdb.MySQLAvailable(); err != nil {
		glog.Errorf("MySQL not available, skipping all MySQL storage tests: %v", err)
		return
	}
	ctx := context.Background()
	var err error
	testDB, err = testdb.New(ctx, rootStoreSQL)
	if err != nil {
		glog.Exitf("failed to create test database: %v", err)
	}
	defer testDB.Close()
	testdb.Clean(ctx, testDB, "Roots")
	ec := m.Run()
	os.Exit(ec)
}

var (
	testDB       *sql.DB
	rootStoreSQL = "root_store.sql"
)
