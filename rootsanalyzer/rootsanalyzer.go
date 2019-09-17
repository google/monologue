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

// Package rootsanalyzer reports on changes in the set of root certificates
// returned by a CT Log's get-roots endpoint.
package rootsanalyzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/url"
	"path"
	"sort"
	"strings"
	"text/template"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/incident"
	"github.com/google/monologue/storage"
)

const logStr = "Roots Analyzer"

var (
	incidentTemplate = template.Must(template.New("roots_incident").Funcs(template.FuncMap{
		"sha256": sha256.Sum256,
	}).Parse(`The root certificates accepted by {{ .Log.Name }} ({{ .Log.URL }}) have changed.
{{ if gt (len .AddedCerts) 0 }}
Certificates added ({{ len .AddedCerts }}):
{{ range .AddedCerts }}{{ .Subject }} (SHA256: {{ sha256 .Raw | printf "%X" }})
{{ end }}{{ end }}{{ if gt (len .RemovedCerts) 0 }}
Certificates removed ({{ len .RemovedCerts }}):
{{ range .RemovedCerts }}{{ .Subject }} (SHA256: {{ sha256 .Raw | printf "%X" }})
{{ end }}{{ end }}`))
)

type incidentTemplateArgs struct {
	Log          *ctlog.Log
	AddedCerts   []*x509.Certificate
	RemovedCerts []*x509.Certificate
}

// Run starts a Roots Analyzer, which watches a CT log's root certificates and creates incident reports for changes to them.
func Run(ctx context.Context, st storage.RootsReader, rep incident.Reporter, l *ctlog.Log) {
	rootSetChan, err := st.WatchRoots(ctx, l)
	if err != nil {
		glog.Errorf("%s: %s: storage.RootsReader.WatchRoots() = %q", l.URL, logStr, err)
		return
	}

	var lastRootSetID storage.RootSetID
	for {
		select {
		case <-ctx.Done():
			return
		case rootSetID := <-rootSetChan:
			if lastRootSetID != "" && lastRootSetID != rootSetID {
				// TODO(RJPercival): If the root set is flapping back to what it recently was, suppress sending an incident report
				// since it could just be the result of skew between log frontends. However, if it doesn't flap back to the new
				// root set again within a certain amount of time, then the suppressed report should be sent.
				oldRoots, err := st.ReadRoots(ctx, lastRootSetID)
				if err != nil {
					glog.Errorf("%s: %s: %s", l.URL, logStr, err)
					return
				}
				newRoots, err := st.ReadRoots(ctx, rootSetID)
				if err != nil {
					glog.Errorf("%s: %s: %s", l.URL, logStr, err)
					return
				}
				addedCerts, removedCerts := diffRootSets(oldRoots, newRoots)
				if err := reportChange(ctx, rep, l, addedCerts, removedCerts); err != nil {
					glog.Errorf("%s: %s: %s", l.URL, logStr, err)
					return
				}
			}
			lastRootSetID = rootSetID
		}
	}
}

// diffRootSets returns the certificates that have been added or removed in new, relative to old.
// Neither old nor new are allowed to contain duplicates.
func diffRootSets(old, new []*x509.Certificate) (added, removed []*x509.Certificate) {
	oldSet := make(map[string]*x509.Certificate, len(old))
	for _, cert := range old {
		oldSet[string(cert.Raw)] = cert
	}
	// This algorithm assumes that there are no duplicates in new.
	// TODO(RJPercival): Support old and new containing duplicate certificates.
	for _, cert := range new {
		certDER := string(cert.Raw)
		if oldSet[certDER] != nil {
			// cert appears in both old and new - remove it from oldSet
			// so that, after the loop, oldSet contains only certs
			// that are in old but not new.
			delete(oldSet, certDER)
		} else {
			// cert is only in new.
			added = append(added, cert)
		}
	}
	for _, cert := range oldSet {
		removed = append(removed, cert)
	}
	return added, removed
}

// sortCerts sorts a slice of certificates first by their subject, then by their raw DER.
func sortCerts(certs []*x509.Certificate) {
	sort.Slice(certs, func(i, j int) bool {
		if subj1, subj2 := certs[i].Subject.String(), certs[j].Subject.String(); subj1 != subj2 {
			return subj1 < subj2
		}
		return bytes.Compare(certs[i].Raw, certs[j].Raw) < 0
	})
}

func reportChange(ctx context.Context, rep incident.Reporter, l *ctlog.Log, addedCerts, removedCerts []*x509.Certificate) error {
	fullURL := l.URL
	getRootsURL, err := url.Parse(l.URL)
	if err != nil {
		glog.Errorf("%s: %s: failed to parse CT Log URL: %v", l.URL, logStr, err)
	} else {
		getRootsURL.Path = path.Join(getRootsURL.Path, ct.GetRootsPath)
		fullURL = getRootsURL.String()
	}

	// Sort certs so that the report is deterministic - makes testing easier.
	sortCerts(addedCerts)
	sortCerts(removedCerts)

	var strBuilder strings.Builder
	if err := incidentTemplate.Execute(&strBuilder, incidentTemplateArgs{
		Log:          l,
		AddedCerts:   addedCerts,
		RemovedCerts: removedCerts,
	}); err != nil {
		return err
	}
	rep.LogUpdate(ctx, l.URL, "Root certificates changed", "roots", fullURL, strBuilder.String())
	return nil
}
