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

package client

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-cmp/cmp"
)

func TestBuildURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		path    string
		params  map[string]string
		want    string
	}{
		{
			name:    "only baseURL",
			baseURL: "https://ct.googleapis.com/pilot/",
			path:    "",
			params:  nil,
			want:    "https://ct.googleapis.com/pilot/",
		},
		{
			name:    "only path",
			baseURL: "",
			path:    "ct/v1/get-sth/",
			params:  nil,
			want:    "ct/v1/get-sth/",
		},
		{
			name:    "nil params",
			baseURL: "https://ct.googleapis.com/pilot/",
			path:    "ct/v1/get-sth",
			params:  nil,
			want:    "https://ct.googleapis.com/pilot/ct/v1/get-sth",
		},
		{
			name:    "nil params, double /",
			baseURL: "https://ct.googleapis.com/pilot/",
			path:    "/ct/v1/get-sth",
			params:  nil,
			want:    "https://ct.googleapis.com/pilot/ct/v1/get-sth",
		},
		{
			name:    "nil params, no /",
			baseURL: "https://ct.googleapis.com/pilot",
			path:    "ct/v1/get-sth",
			params:  nil,
			want:    "https://ct.googleapis.com/pilot/ct/v1/get-sth",
		},
		{
			name:    "empty params",
			baseURL: "https://ct.googleapis.com/pilot/",
			path:    "ct/v1/get-sth",
			params:  map[string]string{},
			want:    "https://ct.googleapis.com/pilot/ct/v1/get-sth",
		},
		{
			name:    "with params",
			baseURL: "https://ct.googleapis.com/pilot/",
			path:    "ct/v1/get-sth-consistency",
			params:  map[string]string{"first": "15", "second": "20"},
			want:    "https://ct.googleapis.com/pilot/ct/v1/get-sth-consistency?first=15&second=20",
		},
		{
			name:    "with params, trailing /",
			baseURL: "https://ct.googleapis.com/pilot/",
			path:    "ct/v1/get-sth-consistency/",
			params:  map[string]string{"first": "15", "second": "20"},
			want:    "https://ct.googleapis.com/pilot/ct/v1/get-sth-consistency?first=15&second=20",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := buildURL(test.baseURL, test.path, test.params); got != test.want {
				t.Fatalf("buildURL(%q, %q, %v) = %q, want %q", test.baseURL, test.path, test.params, got, test.want)
			}
		})
	}
}

func fakeServer(statusCode int, body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write(body)
	}))
}

var sth = "{\"tree_size\":344104340,\"timestamp\":1534165797863,\"sha256_root_hash\":\"ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU=\",\"tree_head_signature\":\"BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8=\"}"

// TODO(katjoyce): Improve these tests - try to find a way to test for all error
// types that could be returned by Get.
func TestGet(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		statusCode  int
		body        []byte
		wantErrType reflect.Type
	}{
		{
			name:        "get error",
			url:         "not-a-real-url",
			wantErrType: reflect.TypeOf(&GetError{}),
		},
		{
			name:        "HTTP status error",
			statusCode:  http.StatusNotFound,
			wantErrType: reflect.TypeOf(&HTTPStatusError{}),
		},
		{
			name:       "no error",
			statusCode: http.StatusOK,
			body:       []byte(sth),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeServer(test.statusCode, test.body)
			lc := New(s.URL, &http.Client{})
			if test.url != "" {
				lc = New(test.url, &http.Client{})
			}

			got, gotErr := lc.get("", nil)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("Get(_, _): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if got == nil {
				t.Fatal("Get(_, _) = nil, _, want an HTTPData containing at least the timing of the request")
			}
			if got.Timing.Start.IsZero() || got.Timing.End.IsZero() {
				t.Errorf("Get(_, _): HTTPData.Timing = %+v, want the Timing to be populated with the timing of the request", got.Timing)
			}
			if !bytes.Equal(got.Body, test.body) {
				t.Errorf("Get(_, _): HTTPData.Body = %s, want %s", got.Body, test.body)
			}
		})
	}
}

func TestGetAndParse(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		statusCode  int
		body        []byte
		wantErrType reflect.Type
	}{
		{
			name:        "get error",
			url:         "not-a-real-url",
			wantErrType: reflect.TypeOf(&GetError{}),
		},
		{
			name:        "HTTP status error",
			statusCode:  http.StatusNotFound,
			wantErrType: reflect.TypeOf(&HTTPStatusError{}),
		},
		{
			name:        "JSON Parse Error",
			statusCode:  http.StatusOK,
			body:        []byte("not-valid-json"),
			wantErrType: reflect.TypeOf(&JSONParseError{}),
		},
		{
			name:       "no error",
			statusCode: http.StatusOK,
			body:       []byte(sth),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeServer(test.statusCode, test.body)
			lc := New(s.URL, &http.Client{})
			if test.url != "" {
				lc = New(test.url, &http.Client{})
			}

			var resp ct.GetSTHResponse
			got, gotErr := lc.getAndParse("", nil, &resp)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("GetAndParse(_, _): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if got == nil {
				t.Fatal("GetAndParse(_, _) = nil, _, want an HTTPData containing at least the timing of the request")
			}
			if got.Timing.Start.IsZero() || got.Timing.End.IsZero() {
				t.Errorf("GetAndParse(_, _): HTTPData.Timing = %+v, want the Timing to be populated with the timing of the request", got.Timing)
			}
			if !bytes.Equal(got.Body, test.body) {
				t.Errorf("GetAndParse(_, _): HTTPData.Body = %s, want %s", got.Body, test.body)
			}
		})
	}
}

func mustB64Decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestGetSTH(t *testing.T) {
	sthShortRootHash := "{\"tree_size\":344104340,\"timestamp\":1534165797863,\"sha256_root_hash\":\"ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJx\",\"tree_head_signature\":\"BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8=\"}"

	tests := []struct {
		name        string
		url         string
		statusCode  int
		body        []byte
		wantErrType reflect.Type
		wantSTH     *ct.GetSTHResponse
	}{
		{
			name:        "get error",
			url:         "not-a-real-url",
			wantErrType: reflect.TypeOf(&GetError{}),
		},
		{
			name:        "HTTP status error",
			statusCode:  http.StatusNotFound,
			wantErrType: reflect.TypeOf(&HTTPStatusError{}),
		},
		{
			name:        "JSON Parse Error",
			statusCode:  http.StatusOK,
			body:        []byte("not-valid-json"),
			wantErrType: reflect.TypeOf(&JSONParseError{}),
		},
		{
			name:        "Response To Struct Error",
			statusCode:  http.StatusOK,
			body:        []byte(sthShortRootHash),
			wantErrType: reflect.TypeOf(&ResponseToStructError{}),
		},
		{
			name:       "no error",
			statusCode: http.StatusOK,
			body:       []byte(sth),
			wantSTH: &ct.GetSTHResponse{
				TreeSize:          344104340,
				Timestamp:         1534165797863,
				SHA256RootHash:    mustB64Decode("ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU="),
				TreeHeadSignature: mustB64Decode("BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8="),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeServer(test.statusCode, test.body)
			lc := New(s.URL, &http.Client{})
			if test.url != "" {
				lc = New(test.url, &http.Client{})
			}

			gotSTH, gotHTTPData, gotErr := lc.GetSTH()
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("GetSTH(): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if gotHTTPData == nil {
				t.Fatal("GetSTH() = nil, _, want an HTTPData containing at least the timing of the request")
			}
			if gotHTTPData.Timing.Start.IsZero() || gotHTTPData.Timing.End.IsZero() {
				t.Errorf("GetSTH(): HTTPData.Timing = %+v, want the Timing to be populated with the timing of the request", gotHTTPData.Timing)
			}
			if !bytes.Equal(gotHTTPData.Body, test.body) {
				t.Errorf("GetSTH(): HTTPData.Body = %s, want %s", gotHTTPData.Body, test.body)
			}

			if gotErr != nil {
				return
			}

			want, err := test.wantSTH.ToSignedTreeHead()
			if err != nil {
				t.Fatalf("ct.GetSTHResponse.ToSignedTreeHead(): %s", err)
			}
			if diff := cmp.Diff(gotSTH, want); diff != "" {
				t.Errorf("GetSTH(): ct.SignedTreeHead diff: (-got +want)\n%s", diff)
			}
		})
	}
}

func marshalCertificates(certs []*x509.Certificate) []string {
	b64 := []string{}
	for _, c := range certs {
		b64 = append(b64, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return b64
}

func TestGetRoots(t *testing.T) {
	rootsB64 := []string{
		"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",
	}

	rootsJSON := fmt.Sprintf(`{"certificates":[%q,%q,%q]}`, rootsB64[0], rootsB64[1], rootsB64[2])

	tests := []struct {
		name         string
		url          string
		statusCode   int
		body         []byte
		wantErrType  reflect.Type
		wantRootsB64 []string
	}{
		{
			name:        "get error",
			url:         "not-a-real-url",
			wantErrType: reflect.TypeOf(&GetError{}),
		},
		{
			name:        "HTTP status error",
			statusCode:  http.StatusNotFound,
			wantErrType: reflect.TypeOf(&HTTPStatusError{}),
		},
		{
			name:        "JSON parse error",
			statusCode:  http.StatusOK,
			body:        []byte("not-valid-json"),
			wantErrType: reflect.TypeOf(&JSONParseError{}),
		},
		{
			name:        "Empty JSON response",
			statusCode:  http.StatusOK,
			body:        []byte(`{}`),
			wantErrType: reflect.TypeOf(&ResponseToStructError{}),
		},
		{
			name:        "Wrong field name in JSON",
			statusCode:  http.StatusOK,
			body:        []byte(`{"chain":[]}`),
			wantErrType: reflect.TypeOf(&ResponseToStructError{}),
		},
		{
			name:         "Empty certificate list",
			statusCode:   http.StatusOK,
			body:         []byte(`{"certificates":[]}`),
			wantRootsB64: []string{},
		},
		{
			name:        "Invalid certificate",
			statusCode:  http.StatusOK,
			body:        []byte(`{"certificates":["foo"]}`),
			wantErrType: reflect.TypeOf(&ResponseToStructError{}),
		},
		{
			name:         "no error",
			statusCode:   http.StatusOK,
			body:         []byte(rootsJSON),
			wantRootsB64: rootsB64,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeServer(test.statusCode, test.body)
			lc := New(s.URL, &http.Client{})
			if test.url != "" {
				lc = New(test.url, &http.Client{})
			}

			gotRoots, gotHTTPData, gotErr := lc.GetRoots()
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Fatalf("GetRoots(): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if gotHTTPData == nil {
				t.Fatal("GetRoots() = nil, _, want an HTTPData containing at least the timing of the request")
			}
			if gotHTTPData.Timing.Start.IsZero() || gotHTTPData.Timing.End.IsZero() {
				t.Errorf("GetRoots(): HTTPData.Timing = %+v, want the Timing to be populated with the timing of the request", gotHTTPData.Timing)
			}
			if !bytes.Equal(gotHTTPData.Body, test.body) {
				t.Errorf("GetRoots(): HTTPData.Body = %s, want %s", gotHTTPData.Body, test.body)
			}

			if gotErr != nil {
				return
			}

			if diff := cmp.Diff(marshalCertificates(gotRoots), test.wantRootsB64); diff != "" {
				t.Errorf("GetRoots(): roots PEM diff: (-got +want)\n%s", diff)
			}
		})
	}
}
