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
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	ct "github.com/google/certificate-transparency-go"
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

var sth = `{"tree_size":344104340,"timestamp":1534165797863,"sha256_root_hash":"ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU=","tree_head_signature":"BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8="}`

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
	sthMissingTreeSize := `{"timestamp":1534165797863,"sha256_root_hash":"ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU=","tree_head_signature":"BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8="}`
	sthMissingTimestamp := `{"tree_size":344104340,"sha256_root_hash":"ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU=","tree_head_signature":"BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8="}`
	sthMissingRootHash := `{"tree_size":344104340,"timestamp":1534165797863,"tree_head_signature":"BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8="}`
	sthMissingSignature := `{"tree_size":344104340,"timestamp":1534165797863,"sha256_root_hash":"ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU="}`
	sthShortRootHash := `{"tree_size":344104340,"timestamp":1534165797863,"sha256_root_hash":"ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJx","tree_head_signature":"BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8="}`

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
			name:       "STH missing tree size",
			statusCode: http.StatusOK,
			body:       []byte(sthMissingTreeSize),
			// TODO(RJPercival): Return error for missing tree_size
			wantSTH: &ct.GetSTHResponse{
				TreeSize:          0,
				Timestamp:         1534165797863,
				SHA256RootHash:    mustB64Decode("ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU="),
				TreeHeadSignature: mustB64Decode("BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8="),
			},
		},
		{
			name:       "STH missing timestamp",
			statusCode: http.StatusOK,
			body:       []byte(sthMissingTimestamp),
			// TODO(RJPercival): Return error for missing timestamp
			wantSTH: &ct.GetSTHResponse{
				TreeSize:          344104340,
				Timestamp:         0,
				SHA256RootHash:    mustB64Decode("ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU="),
				TreeHeadSignature: mustB64Decode("BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8="),
			},
		},
		{
			name:        "STH missing root hash",
			statusCode:  http.StatusOK,
			body:        []byte(sthMissingRootHash),
			wantErrType: reflect.TypeOf(&ResponseToStructError{}),
		},
		{
			name:        "STH missing signature",
			statusCode:  http.StatusOK,
			body:        []byte(sthMissingSignature),
			wantErrType: reflect.TypeOf(&ResponseToStructError{}),
		},
		{
			name:        "STH missing end of root hash",
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
				t.Fatalf("GetSTH(): error was of type %v, want %v", gotErrType, test.wantErrType)
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
