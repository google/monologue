package client

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	ct "github.com/google/certificate-transparency-go"
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

// TODO(katjoyce): Improve this test - it's currently very lightweight.  Try to
// find a way to test for all error types that could be returned by Get.
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
			body:       []byte("{\"tree_size\":344104340,\"timestamp\":1534165797863,\"sha256_root_hash\":\"ygEuQj0whDc1GYzvyAFYMKODrZac2Lu3HOnILxJxIqU=\",\"tree_head_signature\":\"BAMARjBEAiBNI3ZY018rZ0/mGRyadQpDrO7lnAA2zRTuGNBp4YJV7QIgD6gWqMf3nqxxcl6K4Rg6sFi+FClVL2S8sbN3JhfCAs8=\"}"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeServer(test.statusCode, test.body)
			lc := New(s.URL, &http.Client{})
			if test.url != "" {
				lc = New(test.url, &http.Client{})
			}

			got, gotErr := lc.Get(ct.GetSTHPath, nil)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("Get(_, _): error was of type %s, want %s", gotErrType, test.wantErrType)
			}
			if !bytes.Equal(got.Body, test.body) {
				t.Errorf("Get(_, _): HTTPData.Body = %s, want %s", got.Body, test.body)
			}
		})
	}
}
