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

// Package client provides a Certificate Transparency (CT) Log Client that
// prioritizes preserving and returning as much information about each http
// request that is made, and detailed descriptions of any errors that occur
// along the way.
package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

const contentType = "application/json"

// LogClient is a client for a specific CT Log.
//
// Most of the LogClient methods return HTTPData structs and errors.
//
// A returned HTTPData struct contains:
//   - Timing: The time it took for the LogClient's HTTP client to send the
//             request and receive a response.
//   - Response: The http.Response returned by the LogClient's HTTP client, with
//               http.Response.Body already read and closed.
//   - Body: The body of the response received, read from the Body field in the
//           http.Response returned by the LogClient's HTTP client.
// This HTTPData struct will always be returned containing at least the timing
// of the request, even in the case where an error is returned too.
//
// If an error is returned it could be any of the following types, in addition
// to any error types specified in the documentation specific to that method.
// The type of error that is returned influences what the HTTPData struct
// returned will contain:
//   - GetError
//      - HTTPData will contain only the timing of the request.
//   - PostError
//      - HTTPData will contain only the timing of the request.
//   - NilResponseError
//      - HTTPData will contain only the timing of the request.
//   - BodyReadError
//      - HTTPData will contain the timing of the request and the received
//        response.
//   - HTTPStatusError
//      - HTTPData will contain the timing of the request, the received
//        response, and the body of the response.
//   - JSONParseError
//      - HTTPData will contain the timing of the request, the received
//        response, and the body of the response.
type LogClient struct {
	url        string
	httpClient *http.Client
}

// New creates a new LogClient for monitoring the CT Log served at logURL.
func New(logURL string, hc *http.Client) *LogClient {
	return &LogClient{url: logURL, httpClient: hc}
}

// buildURL builds a URL made up of a base URL, a path and a map of parameters.
//
// Example:
//   - Base URL: https://ct.googleapis.com/pilot/
//   - Path: ct/v1/get-sth-consistency
//   - Params: map[string]string{"first":"15", "second":"20"}
//  Result: https://ct.googleapis.com/pilot/ct/v1/get-sth-consistency?first=15&second=20
//
// When concatenating baseURL, path and params, buildURL ensures that only one
// "/" appears between the baseURL and the path, and that no "/" appears between
// the result of concatenating the baseURL and path, and the params.
//
// Example:
//   - Base URL: https://ct.googleapis.com/pilot/
//   - Path: /ct/v1/get-sth-consistency/
//   - Params: map[string]string{"first":"15", "second":"20"}
//  Result: https://ct.googleapis.com/pilot/ct/v1/get-sth-consistency?first=15&second=20
//
// See the tests for further examples.
func buildURL(baseURL, path string, params map[string]string) string {
	var withoutParams string
	if len(baseURL) > 0 && len(path) > 0 {
		// If we need to concatenate a non-empty baseURL and a non-empty path,
		// do it so that exactly one "/" will appear between the two.
		withoutParams = fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), strings.TrimLeft(path, "/"))
	} else {
		// Otherwise, at least one of them is empty, so just concatenating will
		// result in the non-empty one (if there is one) remaining unaltered.
		withoutParams = fmt.Sprintf("%s%s", baseURL, path)
	}

	if len(params) == 0 {
		return withoutParams
	}

	// If there are parameters to be added to the URL, remove any trailing /'s
	// before adding the parameters.
	withoutParams = strings.TrimRight(withoutParams, "/")
	vals := url.Values{}
	for k, v := range params {
		vals.Add(k, v)
	}
	return fmt.Sprintf("%s?%s", withoutParams, vals.Encode())
}

// HTTPData contains information about an HTTP request that was made.
type HTTPData struct {
	Timing   Timing
	Response *http.Response
	Body     []byte
}

// Timing represents an interval of time.  It can be used to represent when an
// event started and ended.
type Timing struct {
	Start time.Time
	End   time.Time
}

// get makes an HTTP GET call to path on the server at lc.url, using the
// parameters provided.
func (lc *LogClient) get(path string, params map[string]string) (*HTTPData, error) {
	httpData := &HTTPData{Timing: Timing{}}

	fullURL := buildURL(lc.url, path, params)
	httpData.Timing.Start = time.Now().UTC()
	resp, err := lc.httpClient.Get(fullURL)
	httpData.Timing.End = time.Now().UTC()
	if err != nil {
		return httpData, &GetError{URL: fullURL, Err: err}
	}

	if resp == nil {
		return httpData, &NilResponseError{URL: fullURL}
	}
	httpData.Response = resp

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return httpData, &BodyReadError{URL: fullURL, Err: err}
	}
	httpData.Body = body

	if resp.StatusCode != http.StatusOK {
		return httpData, &HTTPStatusError{StatusCode: resp.StatusCode}
	}

	return httpData, nil
}

// getAndParse calls get() (see above) and then attempts to parse the JSON
// response body into rsp.
func (lc *LogClient) getAndParse(path string, params map[string]string, rsp interface{}) (*HTTPData, error) {
	httpData, err := lc.get(path, params)
	if err != nil {
		return httpData, err
	}
	if err = json.Unmarshal(httpData.Body, rsp); err != nil {
		return httpData, &JSONParseError{Data: httpData.Body, Err: err}
	}
	return httpData, nil
}

// GetSTH performs a get-sth request.
// Returned is:
//   - a populated ct.SignedTreeHead, if no error is returned.
//   - an HTTPData struct (see above).
//   - an error, which could be any of the error types listed in the LogClient
//     documentation (see above), or a ResponseToStructError.
func (lc *LogClient) GetSTH() (*ct.SignedTreeHead, *HTTPData, error) {
	var resp ct.GetSTHResponse
	httpData, err := lc.getAndParse(ct.GetSTHPath, nil, &resp)
	if err != nil {
		return nil, httpData, err
	}

	sth, err := resp.ToSignedTreeHead()
	if err != nil {
		return nil, httpData, &ResponseToStructError{From: reflect.TypeOf(resp), To: reflect.TypeOf(sth), Err: err}
	}

	return sth, httpData, nil
}

// GetRoots performs a get-roots request.
// Returned is:
//   - a list of certificates, if no error is returned.
//   - the HTTPData struct returned by GetAndParse() (see above).
//   - an error, which could be any of the error types returned by
//     GetAndParse(), or a ResponseToStructError.
func (lc *LogClient) GetRoots() ([]*x509.Certificate, *HTTPData, error) {
	var resp ct.GetRootsResponse
	httpData, err := lc.getAndParse(ct.GetRootsPath, nil, &resp)
	if err != nil {
		return nil, httpData, err
	}

	roots := make([]*x509.Certificate, len(resp.Certificates))

	if resp.Certificates == nil {
		return nil, httpData, &ResponseToStructError{
			From: reflect.TypeOf(resp),
			To:   reflect.TypeOf(roots),
			Err:  fmt.Errorf("no %q field in %q response", "certificates", ct.GetRootsStr),
		}
	}

	for i, certB64 := range resp.Certificates {
		roots[i], err = parseCertificate(certB64)
		if err != nil {
			return nil, httpData, &ResponseToStructError{
				From: reflect.TypeOf(resp),
				To:   reflect.TypeOf(roots),
				Err:  fmt.Errorf("certificates[%d] is invalid: %s", i, err),
			}
		}
	}

	return roots, httpData, nil
}

func parseCertificate(b64 string) (*x509.Certificate, error) {
	certDER, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// post makes an HTTP POST call to path on the server at lc.url, sending the
// body provided.
func (lc *LogClient) post(path string, body []byte) (*HTTPData, error) {
	httpData := &HTTPData{Timing: Timing{}}

	fullURL := buildURL(lc.url, path, nil)
	httpData.Timing.Start = time.Now().UTC()
	resp, err := lc.httpClient.Post(fullURL, contentType, bytes.NewReader(body))
	httpData.Timing.End = time.Now().UTC()
	if err != nil {
		return httpData, &PostError{URL: fullURL, ContentType: contentType, Body: body, Err: err}
	}

	// For the purposes of CT Logs, there should always be a response.
	if resp == nil {
		return httpData, &NilResponseError{URL: fullURL}
	}
	httpData.Response = resp

	rspBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return httpData, &BodyReadError{URL: fullURL, Err: err}
	}
	httpData.Body = rspBody

	if resp.StatusCode != http.StatusOK {
		return httpData, &HTTPStatusError{StatusCode: resp.StatusCode}
	}

	return httpData, nil
}

// postAndParse calls post() (see above) and then attempts to parse the JSON
// response body into rsp.
func (lc *LogClient) postAndParse(path string, body []byte, rsp interface{}) (*HTTPData, error) {
	httpData, err := lc.post(path, body)
	if err != nil {
		return httpData, err
	}
	if err = json.Unmarshal(httpData.Body, rsp); err != nil {
		return httpData, &JSONParseError{Data: httpData.Body, Err: err}
	}
	return httpData, nil
}

// AddChain performs an add-chain request, posting the provided certificate
// chain to the CT Log hosted at LogClient.url.  The first certificate in chain
// should be the end-entity certificate, with the second chaining to the first
// and so on to the last, which should either be the root certificate or a
// certificate that chains to a root certificate that is accepted by the Log.
// Returned is:
//   - a populated ct.SignedCertificateTimestamp, if no error is returned.
//   - an HTTPData struct (see above).
//   - an error, which could be a normal error, any of the error types listed in
//     the LogClient documentation (see above), or a ResponseToStructError.
func (lc *LogClient) AddChain(chain []*x509.Certificate) (*ct.SignedCertificateTimestamp, *HTTPData, error) {
	var req ct.AddChainRequest
	for _, cert := range chain {
		req.Chain = append(req.Chain, cert.Raw)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}

	var resp ct.AddChainResponse
	httpData, err := lc.postAndParse(ct.AddChainPath, body, &resp)
	if err != nil {
		return nil, httpData, err
	}

	sct, err := resp.ToSignedCertificateTimestamp()
	if err != nil {
		return nil, httpData, &ResponseToStructError{From: reflect.TypeOf(resp), To: reflect.TypeOf(sct), Err: err}
	}

	return sct, httpData, nil
}
