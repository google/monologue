// Package monitor provides core and utility types and functions that are useful
// to more than one of the modules that make up the CT monitor.
package monitor

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-monitor/client"
)

// APICall contains the details of a call to one of the API endpoints of a CT
// Log.
type APICall struct {
	Start    time.Time
	End      time.Time
	Endpoint ct.APIEndpoint
	Response *http.Response
	Body     []byte
	Err      error
}

func (ac APICall) String() string {
	lines := []string{
		"APICall {",
		fmt.Sprintf("\tStart: %s", ac.Start),
		fmt.Sprintf("\tEnd: %s", ac.End),
		fmt.Sprintf("\tEndpoint: %s", ac.Endpoint),
		fmt.Sprintf("\tResponse body: %s", ac.Body),
		fmt.Sprintf("\tResponse: %v", ac.Response),
		fmt.Sprintf("\tErr: %v", ac.Err),
		"}",
	}
	return strings.Join(lines, "\n")
}

// CreateAPICall populates and returns an APICall struct using the given
// APIendpoint, HTTPData and error, all of which should relate to the same
// single call to an CT API endpoint.
func CreateAPICall(ep ct.APIEndpoint, httpData *client.HTTPData, err error) *APICall {
	apiCall := &APICall{Endpoint: ep, Err: err}
	if httpData != nil {
		apiCall.Start = httpData.Timing.Start
		apiCall.End = httpData.Timing.End
		apiCall.Response = httpData.Response
		apiCall.Body = httpData.Body
	}
	return apiCall
}
