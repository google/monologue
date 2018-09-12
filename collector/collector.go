// Collector runs a tool to collect the data needed to monitor a single
// Certificate Transparency Log, that can then be used to check that it is
// adhering to RFC 6962.
//
// TODO(katjoyce): Once it contains more functionality, turn this into a package
// so that it can be run on multiple Logs by spinning up one per Log.
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-monitor/client"
	"github.com/google/certificate-transparency-monitor/sthgetter"
	"github.com/google/certificate-transparency-monitor/storage/print"
)

var (
	sthGetPeriod = flag.Duration("sth_get_period", 1*time.Minute, "How regularly the monitor should get an STH from the Log")
	logURL       = flag.String("log_url", "", "The URL of the Log to monitor, e.g. https://ct.googleapis.com/pilot/")
	b64PubKey    = flag.String("public_key", "", "The base64-encoded public key of the Log to monitor")
)

func main() {
	flag.Parse()
	if *logURL == "" {
		log.Fatalf("No Log URL provided.")
	}
	if *b64PubKey == "" {
		log.Fatalf("No public key provided.")
	}

	ctx := context.Background()

	lc := client.New(*logURL, &http.Client{})
	sv, err := sigVerifier(*b64PubKey)
	if err != nil {
		log.Fatalf("Error creating signature verifier: %s", err)
	}

	sthgetter.Run(ctx, lc, sv, &print.Storage{}, *logURL, *sthGetPeriod)
}

func sigVerifier(b64 string) (*ct.SignatureVerifier, error) {
	pk, err := b64ToPubKey(b64)
	if err != nil {
		return nil, err
	}
	return ct.NewSignatureVerifier(pk)
}

func b64ToPubKey(b64 string) (crypto.PublicKey, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64.StdEncoding.DecodeString(%s): %s", b64, err)
	}
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey(): %s", err)
	}
	return pk, nil
}
