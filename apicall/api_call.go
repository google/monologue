// Copyright 2018 Google LLC
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

// Package apicall provides types and functions directly relating to the api
// calls made by the monitor to a Log.
package apicall

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

// New populates and returns an APICall struct using the given APIendpoint,
// HTTPData and error, all of which should relate to the same single call to a
// CT API endpoint.
func New(ep ct.APIEndpoint, httpData *client.HTTPData, err error) *APICall {
	apiCall := &APICall{Endpoint: ep, Err: err}
	if httpData != nil {
		apiCall.Start = httpData.Timing.Start
		apiCall.End = httpData.Timing.End
		apiCall.Response = httpData.Response
		apiCall.Body = httpData.Body
	}
	return apiCall
}
