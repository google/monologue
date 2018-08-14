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
			if got := BuildURL(test.baseURL, test.path, test.params); got != test.want {
				t.Fatalf("BuildURL(%q, %q, %v) = %q, want %q", test.baseURL, test.path, test.params, got, test.want)
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

			got, gotErr := lc.Get("", nil)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("Get(_, _): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if got == nil {
				t.Fatal("Get(_, _) = nil, _, want an HTTPData containing at least the timing of the request")
			}
			if got.Timing == nil || got.Timing.Start.IsZero() || got.Timing.End.IsZero() {
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
			got, gotErr := lc.GetAndParse("", nil, &resp)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("GetAndParse(_, _): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if got == nil {
				t.Fatal("GetAndParse(_, _) = nil, _, want an HTTPData containing at least the timing of the request")
			}
			if got.Timing == nil || got.Timing.Start.IsZero() || got.Timing.End.IsZero() {
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
			if gotHTTPData.Timing == nil || gotHTTPData.Timing.Start.IsZero() || gotHTTPData.Timing.End.IsZero() {
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
