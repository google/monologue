// Package client provides a Certificate Transparency (CT) Log Client that
// prioritizes preserving and returning as much information about each http
// request that is made, and detailed descriptions of any errors that occur
// along the way.
package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

// LogClient is a client for a sepcific CT Log.
type LogClient struct {
	url        string
	HttpClient *http.Client
}

// New creates a new LogClient for monitoring the CT Log served at logURL.
func New(logURL string, hc *http.Client) *LogClient {
	return &LogClient{url: strings.TrimRight(logURL, "/"), HttpClient: hc}
}

// BuildURL builds a URL made up of a base URL, a path and a map of parameters.
//
// Example:
//   - Base URL: https://ct.googleapis.com/pilot/
//   - Path: ct/v1/get-sth-consistency
//   - Params: map[string]string{"first":"15", "second":"20"}
//  Result: https://ct.googleapis.com/pilot/ct/v1/get-sth-consistency?first=15&second=20
//
// When concatenating baseURL, path and params, BuildURL ensures that only one
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
func BuildURL(baseURL, path string, params map[string]string) string {
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

	// If there are paramters to be added to the URL, remove any trailing /'s
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
	Timing   *Timing
	Response *http.Response
	Body     []byte
}

// Timing represents an interval of time.  It can be used to represent when an
// event started and ended.
type Timing struct {
	Start time.Time
	End   time.Time
}

// Get makes an HTTP GET call to path on the server at lc.url, using the
// paramters provided
// Returned is an HTTPData struct containing:
//   - Timing: This is the timing of the inner call to lc.HttpClient.Get(). It
//             is intended to be an estimation of the time the request to the
//             server took.
//   - Response: The http.Response returned from the inner call to
//               lc.HttpClient.Get(), with http.Response.Body already read and
//               closed.
//   - Body: The body of the response received, read from the Body field in the
//           http.Response returned by the inner call to lc.HttpClient.Get().
// This HTTPData struct will always be returned containing at least the timing
// of the inner call to lc.HttpClient.Get() (even in the case where an error is
// returned too).
//
// The error returned could be any of:
//   - GetError
//      -  HTTPData will contain only the timing of the request.
//   - NilResponseError
//      - HTTPData will contain only the timing of the request.
//   - BodyReadError
//      - HTTPData will contain the timing of the request and the received
//        response.
//   - HTTPStatusError
//      - HTTPData will contain the timing of the request, the received
//        response, and the body of the response.
func (lc *LogClient) Get(path string, params map[string]string) (*HTTPData, error) {
	httpData := &HTTPData{Timing: &Timing{}}

	fullURL := BuildURL(lc.url, path, params)
	httpData.Timing.Start = time.Now().UTC()
	resp, err := lc.HttpClient.Get(fullURL)
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

// GetAndParse calls Get() (see above) and then attempts to parse the JSON
// response body into rsp.
// Returned is:
//   - HTTPData: the struct returned from Get().
//   - error: could be any of the error types returned by Get(), or a
//            JSONParseError.
func (lc *LogClient) GetAndParse(path string, params map[string]string, rsp interface{}) (*HTTPData, error) {
	httpData, err := lc.Get(path, params)
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
//   - the HTTPData struct returned by GetAndParse() (see above).
//   - an error, which could be any of the error types returned by
//     GetAndParse(), or a ResponseToStructError.
func (lc *LogClient) GetSTH() (*ct.SignedTreeHead, *HTTPData, error) {
	var resp ct.GetSTHResponse
	httpData, err := lc.GetAndParse(ct.GetSTHPath, nil, &resp)
	if err != nil {
		return nil, httpData, err
	}

	sth, err := resp.ToSignedTreeHead()
	if err != nil {
		return nil, httpData, &ResponseToStructError{From: reflect.TypeOf(resp), To: reflect.TypeOf(sth), Err: err}
	}

	return sth, httpData, nil
}
