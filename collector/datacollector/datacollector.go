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

// Datacollector runs a tool to collect the data needed to monitor Certificate
// Transparency Logs, which can then be used to check that they are adhering to
// RFC 6962.
package main

import (
	"context"
	"flag"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/monologue/certgen"
	"github.com/google/monologue/collector"
	"github.com/google/monologue/ctlog"
	"github.com/google/monologue/storage/print"
	"github.com/google/trillian/crypto/keys/pem"
)

var (
	getRootsPeriod = flag.Duration("get_roots_period", 0, "How regularly the monitor should get root certificates from the Log")
	getSTHPeriod   = flag.Duration("get_sth_period", 0, "How regularly the monitor should get an STH from the Log")
	addChainPeriod = flag.Duration("add_chain_period", 0, "How regularly the monitor should submit a (pre-)certificate to the Log")
	// TODO(katjoyce): Change to read from log_list.json or all_logs_list.json to get Log details.
	// TODO(katjoyce): Add ability to run against multiple Logs.
	logURL    = flag.String("log_url", "", "The URL of the Log to monitor, e.g. https://ct.googleapis.com/pilot/")
	logName   = flag.String("log_name", "", "A short, snappy, canonical name for the Log to monitor, e.g. google_pilot")
	b64PubKey = flag.String("public_key", "", "The base64-encoded public key of the Log to monitor")
	mmd       = flag.Duration("mmd", 24*time.Hour, "The Maximum Merge Delay for the Log")

	signingCertFile = flag.String("signing_cert", "", "Path to the certificate containing the public key that corresponds to the signing key. Only needed if add_chain_period is not 0")
	signingKeyFile  = flag.String("signing_key", "", "Path to the private key for signing certificates to submit to the Log. Only needed if add_chain_period is not 0")
)

func main() {
	flag.Parse()
	if *logURL == "" {
		glog.Exit("No Log URL provided.")
	}
	if *logName == "" {
		glog.Exit("No Log name provided.")
	}
	if *b64PubKey == "" {
		glog.Exit("No public key provided.")
	}

	ctx := context.Background()
	l, err := ctlog.New(*logURL, *logName, *b64PubKey, *mmd, nil)
	if err != nil {
		glog.Exitf("Unable to obtain Log metadata: %s", err)
	}

	var ca *certgen.CA
	if *addChainPeriod > 0 {
		// TODO(katjoyce): Add support for other key encodings and
		// generally improve key management here.
		signingCertPEM, err := ioutil.ReadFile(*signingCertFile)
		if err != nil {
			glog.Exitf("Error reading signing cert from %s: %s", *signingCertFile, err)
		}
		signingCert, err := x509util.CertificateFromPEM(signingCertPEM)
		if err != nil {
			glog.Exitf("Error parsing signing cert: %s", err)
		}

		signingKeyPEM, err := ioutil.ReadFile(*signingKeyFile)
		if err != nil {
			glog.Exitf("Error reading signing key from %s: %s", *signingKeyFile, err)
		}
		signingKey, err := pem.UnmarshalPrivateKey(string(signingKeyPEM), "")
		if err != nil {
			glog.Exitf("Error parsing signing key: %s", err)
		}

		certConfig := certgen.CertificateConfig{
			SubjectCommonName:         "flowers-to-the-world.com",
			SubjectOrganization:       "Google",
			SubjectOrganizationalUnit: "Certificate Transparency",
			SubjectLocality:           "London",
			SubjectCountry:            "GB",
			SignatureAlgorithm:        x509.SHA256WithRSA,
			DNSPrefix:                 l.Name,
		}

		ca = &certgen.CA{
			SigningCert: signingCert,
			SigningKey:  signingKey,
			CertConfig:  certConfig,
		}
	}

	cfg := &collector.Config{
		Log:            l,
		GetSTHPeriod:   *getSTHPeriod,
		GetRootsPeriod: *getRootsPeriod,
		AddChainPeriod: *addChainPeriod,
		CA:             ca,
	}

	if err := collector.Run(ctx, cfg, &http.Client{}, &print.Storage{}); err != nil {
		glog.Exit(err)
	}
}
