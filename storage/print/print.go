// Package print provides a concrete implementation of the storage interfaces
// needed by the CT monitor, which simply prints everything that is passed to it
// to be 'stored'.
//
// This package is only intended to be a handy tool used during development, and
// will likely be deleted in the not-so-distant future.  Don't rely on it.
package print

import (
	"context"
	"log"

	monitor "github.com/google/certificate-transparency-monitor"
)

// Storage implements the storage interfaces needed by the CT monitor.
type Storage struct{}

// WriteAPICall simply prints the API Call passed to it.
func (s *Storage) WriteAPICall(ctx context.Context, apiCall *monitor.APICall) error {
	log.Println(apiCall.String())
	return nil
}
