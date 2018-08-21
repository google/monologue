// Package storage provides the storage interfaces required by the various
// pieces of the CT monitor.
package storage

import (
	"context"

	monitor "github.com/google/certificate-transparency-monitor"
)

// APICallWriter is an interface for storing individual calls to CT API
// endpoints.
type APICallWriter interface {
	WriteAPICall(ctx context.Context, apiCall *monitor.APICall) error
}
