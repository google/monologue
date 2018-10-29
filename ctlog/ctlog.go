// Package ctlog contains data structures and methods to do with CT Log metadata
// that is needed by the monitor.
//
// TODO(katjoyce): Try to come up with a better package name.
package ctlog

import (
	"crypto"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/logid"
)

// Log represents a CT Log and contains the Log metadata needed by the monitor.
type Log struct {
	ID        logid.LogID
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
	id, err := logid.FromPubKeyB64(b64PubKey)
	if err != nil {
		return nil, fmt.Errorf("logid.FromPubKeyB64(): %s", err)
	}
	pk, err := ct.PublicKeyFromB64(b64PubKey)
	if err != nil {
		return nil, fmt.Errorf("ct.PublicKeyFromB64(): %s", err)
	}
	return &Log{
		ID:        id,
		Name:      name,
		URL:       url,
		PublicKey: pk,
	}, nil
}
