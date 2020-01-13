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
	"github.com/google/certificate-transparency-go/x509util"
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
				t.Errorf("GetSTH(): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if gotHTTPData == nil {
				t.Fatal("GetSTH() = (_, nil, _), want an HTTPData containing at least the timing of the request")
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

var (
	// Certificate:
	// Data:
	//     Version: 3 (0x2)
	//     Serial Number:
	//         9e:d3:cc:b1:d1:2c:a2:72
	//     Signature Algorithm: sha1WithRSAEncryption
	//     Issuer: C = GB, ST = London, O = Google UK Ltd., OU = Certificate Transparency, CN = Merge Delay Monitor Root
	//     Validity
	//         Not Before: Jul 17 12:05:43 2014 GMT
	//         Not After : Dec  2 12:05:43 2041 GMT
	//     Subject: C = GB, ST = London, O = Google UK Ltd., OU = Certificate Transparency, CN = Merge Delay Monitor Root
	//     Subject Public Key Info:
	//         Public Key Algorithm: rsaEncryption
	//             RSA Public-Key: (4096 bit)
	//             Modulus:
	//                 00:aa:16:1c:f2:20:5e:d8:1a:c5:65:48:3c:da:42:
	//                 6a:3d:b2:e5:88:fd:b7:58:b1:7b:93:ea:8d:68:49:
	//                 5d:53:4a:01:ba:4f:6c:d1:c0:fc:0a:12:8a:f7:9c:
	//                 06:6d:c5:4c:3f:43:7e:05:ba:27:5e:e6:1d:bf:9c:
	//                 bd:b2:92:81:83:73:81:39:39:7b:61:89:ae:73:8f:
	//                 ef:2b:9b:60:9a:6d:d8:e0:b0:d0:e2:0b:24:3d:b9:
	//                 36:c0:29:cd:c2:22:0a:f2:c0:e1:a5:e4:aa:41:a0:
	//                 06:af:45:89:57:e2:b1:17:8d:27:15:6e:f0:cb:71:
	//                 7e:16:d5:40:25:d9:7f:43:e9:91:6f:b2:40:fb:85:
	//                 f7:d5:79:46:2f:a0:ac:76:c7:62:56:84:37:50:bf:
	//                 1c:cd:fe:b7:6c:8c:47:88:64:77:64:4d:5e:c3:23:
	//                 56:28:ad:f6:a0:9c:84:88:bf:a5:03:6d:e7:17:90:
	//                 81:51:a6:b5:85:f2:73:dd:9f:b5:33:2b:9a:f7:6e:
	//                 8f:bf:a9:1e:af:43:11:81:6d:de:27:c5:c4:4f:2f:
	//                 d0:6c:c2:20:4d:71:47:f7:7b:a6:b1:6a:2a:5f:ca:
	//                 47:00:23:61:47:29:53:8b:ee:6b:3c:b0:72:64:71:
	//                 38:32:ae:c1:61:55:0e:b5:01:90:68:02:21:52:23:
	//                 ac:c2:56:4a:d1:f9:8b:b5:93:49:24:eb:56:d3:83:
	//                 fc:75:98:be:45:c8:9d:99:52:81:c0:ef:b0:d2:06:
	//                 d2:9a:6d:25:a1:0a:48:fe:23:53:32:37:9c:5c:a6:
	//                 9e:83:59:9f:aa:67:7d:d2:08:23:f5:c8:4a:96:12:
	//                 55:ec:a5:d4:87:1d:54:ca:1d:f0:77:4a:a1:17:b0:
	//                 f4:2c:d6:e9:fd:a7:e8:a4:8a:53:92:3c:5f:94:04:
	//                 33:53:54:4e:64:4b:5a:65:62:e5:ce:f9:fc:2b:d2:
	//                 fc:fc:ce:33:23:33:5c:f7:fe:7c:4d:83:c1:b7:f8:
	//                 39:c4:79:01:92:d3:ba:9a:a9:f3:20:93:aa:8e:e7:
	//                 cb:e7:08:05:9d:53:8d:c6:63:cc:a1:b8:25:33:1a:
	//                 a8:36:75:4a:0d:13:de:63:bf:65:b6:e2:04:4d:cd:
	//                 f0:41:f1:a0:c5:a9:c3:c3:8f:e7:4c:f5:76:d4:51:
	//                 c2:3e:aa:51:9d:b3:2e:f9:e0:39:bd:84:8a:19:4c:
	//                 3b:5e:41:a5:56:42:dc:28:3d:db:d7:3d:1d:d9:7a:
	//                 e6:95:1d:e1:8a:d8:9d:00:50:07:fa:e7:e8:8b:c7:
	//                 a3:cc:e8:b7:cc:c4:96:03:a0:db:67:c7:6d:58:a2:
	//                 8d:4b:77:aa:74:60:80:1e:34:37:7d:0c:5e:46:06:
	//                 c2:e2:5b
	//             Exponent: 65537 (0x10001)
	//     X509v3 extensions:
	//         X509v3 Subject Key Identifier:
	//             F3:5F:7B:75:49:E3:78:41:39:6A:20:B6:7C:6B:4C:5C:C9:3D:58:41
	//         X509v3 Authority Key Identifier:
	//             keyid:F3:5F:7B:75:49:E3:78:41:39:6A:20:B6:7C:6B:4C:5C:C9:3D:58:41
	//
	//         X509v3 Basic Constraints:
	//             CA:TRUE
	// Signature Algorithm: sha1WithRSAEncryption
	//      77:1c:fe:a3:45:79:a9:75:20:d8:c2:42:3d:68:ec:d0:78:91:
	//      f8:c7:f1:c3:8b:f3:cd:30:ea:9d:36:37:bf:c5:d3:73:53:2e:
	//      c7:65:65:58:be:f4:95:06:46:75:0c:6f:e0:85:c5:2d:9f:fc:
	//      09:e6:6e:bf:a2:b0:67:de:77:27:cb:38:1d:2b:25:db:58:b9:
	//      c2:19:7f:d5:eb:53:e0:20:f4:29:b8:6a:3b:1f:37:a0:7a:76:
	//      1a:66:a5:b3:ec:d7:97:c4:66:95:a3:7f:f2:d4:7c:54:12:6b:
	//      e6:bd:28:a2:a1:03:35:72:27:c6:b7:3f:7f:68:9b:09:b4:89:
	//      27:e6:e9:a5:22:67:a7:28:a1:15:d4:bc:bb:47:75:33:dc:28:
	//      f3:fc:57:da:73:5a:3e:c5:4f:bc:36:99:0b:17:fe:bb:7e:46:
	//      b3:24:20:8c:1f:a7:42:5a:0c:ba:48:bd:c0:38:1e:a8:28:52:
	//      15:26:1c:3c:48:3f:2f:a6:d1:da:0d:ba:49:49:10:71:89:f3:
	//      2d:72:8a:7f:f3:95:d4:34:30:af:3b:8c:e4:be:50:75:bc:f6:
	//      7d:66:66:19:41:dc:8b:e3:73:40:f8:f9:28:2b:2d:2a:ad:d6:
	//      90:65:93:2a:d4:97:69:f8:bc:7f:c9:e5:f6:e7:9f:f3:92:42:
	//      0b:a7:8d:e3:17:27:78:e2:b6:7e:4d:f1:84:40:dd:56:1e:5a:
	//      78:44:c8:ef:a0:6c:0e:5f:5b:86:95:fa:06:91:14:a0:05:18:
	//      fb:4c:19:f9:d7:85:58:31:b5:ee:eb:ce:d1:4b:85:98:da:ff:
	//      a4:9f:2d:cf:50:5b:ff:64:17:d8:4b:28:e8:35:99:d4:e0:37:
	//      1e:f6:4b:2d:82:ff:a0:68:a3:10:44:f7:32:2f:ee:2f:65:4e:
	//      c3:57:c9:c1:21:f3:45:8a:50:97:28:c3:7f:56:73:41:2a:d0:
	//      d5:e7:6a:a6:b4:eb:15:82:18:1a:8b:e4:04:d3:dc:35:e7:1e:
	//      dd:83:ee:38:80:87:d6:14:7c:4d:86:f1:ca:ca:cf:ac:e0:10:
	//      4d:f1:f4:b1:00:c2:ce:b1:be:4d:18:51:c4:f3:1e:7c:44:09:
	//      26:21:85:87:8f:23:cc:eb:30:79:01:43:f0:d5:bd:80:d2:c0:
	//      ed:42:60:aa:a3:12:59:7d:95:0a:af:3c:8b:cf:c8:12:d9:a5:
	//      6e:8d:16:0d:d7:72:a4:94:74:37:10:a7:e4:78:a0:46:d8:a5:
	//      d5:05:ee:6b:8c:c3:7f:ec:09:df:d4:cb:57:c6:c4:d8:e8:ef:
	//      2a:22:e1:d9:e5:09:57:85:26:33:13:8d:72:22:53:e5:1b:a7:
	//      7b:00:69:d3:88:12:20:7a
	rootPEM = `-----BEGIN CERTIFICATE-----                                                      
MIIFzTCCA7WgAwIBAgIJAJ7TzLHRLKJyMA0GCSqGSIb3DQEBBQUAMH0xCzAJBgNV                 
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xFzAVBgNVBAoMDkdvb2dsZSBVSyBMdGQu                 
MSEwHwYDVQQLDBhDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kxITAfBgNVBAMMGE1l                 
cmdlIERlbGF5IE1vbml0b3IgUm9vdDAeFw0xNDA3MTcxMjA1NDNaFw00MTEyMDIx                 
MjA1NDNaMH0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xFzAVBgNVBAoM                 
Dkdvb2dsZSBVSyBMdGQuMSEwHwYDVQQLDBhDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVu                 
Y3kxITAfBgNVBAMMGE1lcmdlIERlbGF5IE1vbml0b3IgUm9vdDCCAiIwDQYJKoZI                 
hvcNAQEBBQADggIPADCCAgoCggIBAKoWHPIgXtgaxWVIPNpCaj2y5Yj9t1ixe5Pq                 
jWhJXVNKAbpPbNHA/AoSivecBm3FTD9DfgW6J17mHb+cvbKSgYNzgTk5e2GJrnOP                 
7yubYJpt2OCw0OILJD25NsApzcIiCvLA4aXkqkGgBq9FiVfisReNJxVu8MtxfhbV                 
QCXZf0PpkW+yQPuF99V5Ri+grHbHYlaEN1C/HM3+t2yMR4hkd2RNXsMjViit9qCc                 
hIi/pQNt5xeQgVGmtYXyc92ftTMrmvduj7+pHq9DEYFt3ifFxE8v0GzCIE1xR/d7                 
prFqKl/KRwAjYUcpU4vuazywcmRxODKuwWFVDrUBkGgCIVIjrMJWStH5i7WTSSTr                 
VtOD/HWYvkXInZlSgcDvsNIG0pptJaEKSP4jUzI3nFymnoNZn6pnfdIII/XISpYS                 
Veyl1IcdVMod8HdKoRew9CzW6f2n6KSKU5I8X5QEM1NUTmRLWmVi5c75/CvS/PzO                 
MyMzXPf+fE2Dwbf4OcR5AZLTupqp8yCTqo7ny+cIBZ1TjcZjzKG4JTMaqDZ1Sg0T                 
3mO/ZbbiBE3N8EHxoMWpw8OP50z1dtRRwj6qUZ2zLvngOb2EihlMO15BpVZC3Cg9                 
29c9Hdl65pUd4YrYnQBQB/rn6IvHo8zot8zElgOg22fHbViijUt3qnRggB40N30M                 
XkYGwuJbAgMBAAGjUDBOMB0GA1UdDgQWBBTzX3t1SeN4QTlqILZ8a0xcyT1YQTAf                 
BgNVHSMEGDAWgBTzX3t1SeN4QTlqILZ8a0xcyT1YQTAMBgNVHRMEBTADAQH/MA0G                 
CSqGSIb3DQEBBQUAA4ICAQB3HP6jRXmpdSDYwkI9aOzQeJH4x/HDi/PNMOqdNje/                 
xdNzUy7HZWVYvvSVBkZ1DG/ghcUtn/wJ5m6/orBn3ncnyzgdKyXbWLnCGX/V61Pg                 
IPQpuGo7HzegenYaZqWz7NeXxGaVo3/y1HxUEmvmvSiioQM1cifGtz9/aJsJtIkn                 
5umlImenKKEV1Ly7R3Uz3Cjz/Ffac1o+xU+8NpkLF/67fkazJCCMH6dCWgy6SL3A                 
OB6oKFIVJhw8SD8vptHaDbpJSRBxifMtcop/85XUNDCvO4zkvlB1vPZ9ZmYZQdyL                 
43NA+PkoKy0qrdaQZZMq1Jdp+Lx/yeX255/zkkILp43jFyd44rZ+TfGEQN1WHlp4                 
RMjvoGwOX1uGlfoGkRSgBRj7TBn514VYMbXu687RS4WY2v+kny3PUFv/ZBfYSyjo                 
NZnU4Dce9kstgv+gaKMQRPcyL+4vZU7DV8nBIfNFilCXKMN/VnNBKtDV52qmtOsV                 
ghgai+QE09w15x7dg+44gIfWFHxNhvHKys+s4BBN8fSxAMLOsb5NGFHE8x58RAkm                 
IYWHjyPM6zB5AUPw1b2A0sDtQmCqoxJZfZUKrzyLz8gS2aVujRYN13KklHQ3EKfk                 
eKBG2KXVBe5rjMN/7Anf1MtXxsTY6O8qIuHZ5QlXhSYzE41yIlPlG6d7AGnTiBIg                 
eg==                                                                             
-----END CERTIFICATE-----`

	// Certificate:
	// Data:
	//     Version: 3 (0x2)
	//     Serial Number: 4097 (0x1001)
	//     Signature Algorithm: sha1WithRSAEncryption
	//     Issuer: C = GB, ST = London, O = Google UK Ltd., OU = Certificate Transparency, CN = Merge Delay Monitor Root
	//     Validity
	//         Not Before: Jul 17 12:26:30 2014 GMT
	//         Not After : Jul 16 12:26:30 2019 GMT
	//     Subject: C = GB, ST = London, O = Google UK Ltd., OU = Certificate Transparency, CN = Merge Delay Intermediate 1
	//     Subject Public Key Info:
	//         Public Key Algorithm: rsaEncryption
	//             RSA Public-Key: (4096 bit)
	//             Modulus:
	//                 00:c1:e8:74:fe:ff:9a:ee:f3:03:bb:fa:63:45:38:
	//                 81:fa:af:8d:c1:c2:2c:09:64:1d:af:43:03:81:f3:
	//                 3b:c1:57:bf:6c:4c:8a:8d:57:b1:ab:c7:92:85:9d:
	//                 20:f2:19:15:09:c5:97:c4:37:b1:46:73:de:a5:af:
	//                 4b:ea:14:39:6d:d4:36:dc:62:05:55:d7:95:3e:0e:
	//                 de:01:f7:ff:b4:4f:3f:f7:cd:e6:4e:d2:45:63:4e:
	//                 0d:f0:aa:fc:e9:c3:ac:5e:b6:3d:8d:e1:d9:69:ca:
	//                 c8:85:41:95:40:3a:9f:9d:1d:4c:3d:ce:ed:f1:35:
	//                 1e:dd:94:57:43:bc:54:ab:74:5b:20:4f:b5:25:9f:
	//                 e3:ed:f6:95:c2:cf:90:b8:86:c4:8f:f6:80:b7:44:
	//                 fe:c2:69:1b:43:45:24:2b:31:c3:6f:31:18:b7:27:
	//                 c5:de:5c:25:ec:1a:a3:0a:4c:24:61:c5:11:9e:f6:
	//                 bb:90:d8:16:e6:e4:4c:5b:99:55:bf:a2:ed:34:16:
	//                 bf:6e:4a:53:c9:2f:af:ac:0d:1f:0b:8b:f3:d3:5b:
	//                 e0:d4:f6:1c:a0:5d:28:fc:66:2d:fa:58:8f:ba:3e:
	//                 e0:38:04:70:c0:12:de:d9:e5:1b:bf:1e:7a:25:ef:
	//                 a7:45:78:4c:49:d0:5e:af:8d:ce:e0:52:73:61:ec:
	//                 91:31:26:00:5e:97:2c:f4:b8:63:91:4f:83:61:58:
	//                 2e:d2:45:63:ff:9e:03:c5:2e:8a:9c:a3:26:4c:56:
	//                 c1:86:b4:ec:52:b7:e6:95:ce:42:ae:17:ec:7a:e0:
	//                 25:71:31:e1:db:f4:8f:2d:de:24:2e:6e:91:ea:30:
	//                 49:88:13:5a:15:48:2b:05:fc:09:13:55:32:8b:39:
	//                 e5:86:e8:dd:3a:4a:3a:14:cb:97:ee:f6:8f:9f:69:
	//                 72:8c:29:1f:21:95:d2:cc:e7:3d:4a:e9:08:45:b1:
	//                 bf:c5:fa:e0:40:b9:4f:c3:59:a2:95:11:98:1b:99:
	//                 66:ae:b5:6d:3a:7c:5e:48:f8:ec:a8:15:e5:be:86:
	//                 b3:d3:6e:6a:27:e0:e2:c4:de:e6:e3:0f:12:a7:c9:
	//                 36:b8:c9:8c:ad:59:28:ac:a2:38:df:c3:9c:f9:f2:
	//                 c5:24:6c:bb:bb:28:0c:b6:f9:9e:b4:9b:fd:1d:78:
	//                 08:95:39:07:2c:16:4c:70:83:37:17:46:de:db:c4:
	//                 de:c1:cb:94:39:07:3a:f3:f2:e6:0f:8c:50:5f:06:
	//                 79:61:a8:c5:39:45:4f:c5:34:11:58:ec:cc:78:53:
	//                 2f:3e:39:c3:18:7c:94:39:fc:0f:f8:8e:e9:57:13:
	//                 1d:47:8d:f0:63:dd:50:b2:ad:3f:e7:a0:70:e9:05:
	//                 e3:86:8b
	//             Exponent: 65537 (0x10001)
	//     X509v3 extensions:
	//         X509v3 Subject Key Identifier:
	//             E9:3C:04:E1:80:2F:C2:84:13:2D:26:70:9E:F2:FD:1A:CF:AA:FE:C6
	//         X509v3 Authority Key Identifier:
	//             keyid:F3:5F:7B:75:49:E3:78:41:39:6A:20:B6:7C:6B:4C:5C:C9:3D:58:41
	//
	//         X509v3 Basic Constraints:
	//             CA:TRUE
	// Signature Algorithm: sha1WithRSAEncryption
	//      08:58:cb:d5:45:f2:e9:2e:09:90:6a:c3:9f:3d:55:c1:36:07:
	//      a6:51:43:63:86:c6:e9:0f:12:87:73:a0:eb:3f:47:25:d8:af:
	//      35:fb:7f:88:04:36:b4:81:f2:cf:47:80:18:25:de:54:f1:3f:
	//      8f:59:20:bf:3d:91:6e:75:31:41:de:5e:59:d2:de:bb:fc:3f:
	//      c2:26:72:1f:15:a1:6d:3b:7a:46:18:ea:05:51:63:9f:1d:2c:
	//      b7:b9:fa:ad:1b:7e:07:0f:23:a6:e8:19:7c:3d:75:49:bb:a6:
	//      55:3f:d5:db:41:9c:e3:99:47:7f:6a:04:81:b9:0f:51:c9:d3:
	//      07:d8:2c:b0:5c:f9:67:82:8a:1a:ce:65:20:7c:f8:6b:6d:16:
	//      79:22:45:dc:f2:4b:4c:17:9f:91:18:47:36:e7:e2:fc:b8:63:
	//      a4:b5:c8:9b:0a:c2:f3:68:39:0a:10:59:4b:95:c8:56:e2:59:
	//      c7:75:64:31:68:98:cf:87:a6:81:7d:18:58:5f:c9:76:d6:81:
	//      d9:d5:10:ef:2a:d3:7e:8a:d0:e4:9f:5b:d4:99:c9:ec:7f:e8:
	//      f4:3b:17:df:fb:9b:7d:0d:fd:83:00:c1:c5:38:9c:9e:a0:be:
	//      43:70:dc:bf:78:bd:3e:fc:23:08:d2:50:b8:66:bb:ca:03:1c:
	//      0c:49:ff:77:a7:a5:42:0d:aa:1f:1b:6a:44:4d:36:66:53:97:
	//      4c:2d:17:9c:30:09:87:1e:e6:c8:91:40:fc:a9:ef:df:23:bd:
	//      4b:88:c6:eb:ae:b9:28:6f:58:f3:cf:c2:1e:48:74:f1:82:d1:
	//      ec:d6:05:89:19:b0:3b:18:db:7b:79:5b:e9:cb:25:fc:51:66:
	//      a9:45:ef:8e:11:33:cd:60:31:2a:32:34:f4:64:9d:f6:16:64:
	//      07:cb:b5:ec:c8:38:e9:e1:18:c0:5d:ee:7c:89:6a:99:87:65:
	//      5a:e7:e3:49:cd:81:66:e6:8d:34:de:a3:b4:ae:89:2a:9f:23:
	//      85:05:32:71:e8:60:b5:42:be:36:50:50:39:74:f3:bb:6f:26:
	//      88:37:5a:b2:84:87:da:67:51:d0:f2:c3:a3:5e:78:ef:e3:0b:
	//      19:d5:78:08:eb:ea:2c:44:53:99:0a:d8:1e:b9:62:89:c0:f9:
	//      9c:50:80:f8:20:92:bc:61:23:a3:40:c6:3a:61:7f:3b:c4:ad:
	//      c1:29:8d:88:a2:78:a6:93:ef:93:68:86:11:d3:b4:ed:ed:0b:
	//      6d:02:3e:d9:f6:c2:ea:88:36:48:31:97:52:5b:1b:1b:ce:70:
	//      a9:0c:34:03:b0:94:d5:f4:12:aa:11:41:b9:96:5a:b8:31:4c:
	//      52:f7:72:de:ff:c1:00:8c
	intermediatePEM = `-----BEGIN CERTIFICATE-----                                                      
MIIF9jCCA7CgAwIBAgICEAEwDQYJKoZIhvcNAQEFBQAwfTELMAkGA1UEBhMCR0Ix                 
DzANBgNVBAgMBkxvbmRvbjEXMBUGA1UECgwOR29vZ2xlIFVLIEx0ZC4xITAfBgNV                 
BAsMGENlcnRpZmljYXRlIFRyYW5zcGFyZW5jeTEhMB8GA1UEAwwYTWVyZ2UgRGVs                 
YXkgTW9uaXRvciBSb290MB4XDTE0MDcxNzEyMjYzMFoXDTE5MDcxNjEyMjYzMFow                 
fzELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEXMBUGA1UECgwOR29vZ2xl                 
IFVLIEx0ZC4xITAfBgNVBAsMGENlcnRpZmljYXRlIFRyYW5zcGFyZW5jeTEjMCEG                 
A1UEAwwaTWVyZ2UgRGVsYXkgSW50ZXJtZWRpYXRlIDEwggIiMA0GCSqGSIb3DQEB                 
AQUAA4ICDwAwggIKAoICAQDB6HT+/5ru8wO7+mNFOIH6r43BwiwJZB2vQwOB8zvB                 
V79sTIqNV7Grx5KFnSDyGRUJxZfEN7FGc96lr0vqFDlt1DbcYgVV15U+Dt4B9/+0                 
Tz/3zeZO0kVjTg3wqvzpw6xetj2N4dlpysiFQZVAOp+dHUw9zu3xNR7dlFdDvFSr                 
dFsgT7Uln+Pt9pXCz5C4hsSP9oC3RP7CaRtDRSQrMcNvMRi3J8XeXCXsGqMKTCRh                 
xRGe9ruQ2Bbm5ExbmVW/ou00Fr9uSlPJL6+sDR8Li/PTW+DU9hygXSj8Zi36WI+6                 
PuA4BHDAEt7Z5Ru/Hnol76dFeExJ0F6vjc7gUnNh7JExJgBelyz0uGORT4NhWC7S                 
RWP/ngPFLoqcoyZMVsGGtOxSt+aVzkKuF+x64CVxMeHb9I8t3iQubpHqMEmIE1oV                 
SCsF/AkTVTKLOeWG6N06SjoUy5fu9o+faXKMKR8hldLM5z1K6QhFsb/F+uBAuU/D                 
WaKVEZgbmWautW06fF5I+OyoFeW+hrPTbmon4OLE3ubjDxKnyTa4yYytWSisojjf                 
w5z58sUkbLu7KAy2+Z60m/0deAiVOQcsFkxwgzcXRt7bxN7By5Q5Bzrz8uYPjFBf                 
BnlhqMU5RU/FNBFY7Mx4Uy8+OcMYfJQ5/A/4julXEx1HjfBj3VCyrT/noHDpBeOG                 
iwIDAQABo1AwTjAdBgNVHQ4EFgQU6TwE4YAvwoQTLSZwnvL9Gs+q/sYwHwYDVR0j                 
BBgwFoAU8197dUnjeEE5aiC2fGtMXMk9WEEwDAYDVR0TBAUwAwEB/zA7BgkqhkiG                 
9w0BAQUTLlRoaXMgaXMgbm90IHRoZSBjZXJ0aWZpY2F0ZSB5b3UncmUgbG9va2lu                 
ZyBmb3IDggIBAAhYy9VF8ukuCZBqw589VcE2B6ZRQ2OGxukPEodzoOs/RyXYrzX7                 
f4gENrSB8s9HgBgl3lTxP49ZIL89kW51MUHeXlnS3rv8P8Imch8VoW07ekYY6gVR                 
Y58dLLe5+q0bfgcPI6boGXw9dUm7plU/1dtBnOOZR39qBIG5D1HJ0wfYLLBc+WeC                 
ihrOZSB8+GttFnkiRdzyS0wXn5EYRzbn4vy4Y6S1yJsKwvNoOQoQWUuVyFbiWcd1                 
ZDFomM+HpoF9GFhfyXbWgdnVEO8q036K0OSfW9SZyex/6PQ7F9/7m30N/YMAwcU4                 
nJ6gvkNw3L94vT78IwjSULhmu8oDHAxJ/3enpUINqh8bakRNNmZTl0wtF5wwCYce                 
5siRQPyp798jvUuIxuuuuShvWPPPwh5IdPGC0ezWBYkZsDsY23t5W+nLJfxRZqlF                 
744RM81gMSoyNPRknfYWZAfLtezIOOnhGMBd7nyJapmHZVrn40nNgWbmjTTeo7Su                 
iSqfI4UFMnHoYLVCvjZQUDl087tvJog3WrKEh9pnUdDyw6NeeO/jCxnVeAjr6ixE                 
U5kK2B65YonA+ZxQgPggkrxhI6NAxjphfzvErcEpjYiieKaT75NohhHTtO3tC20C                 
Ptn2wuqINkgxl1JbGxvOcKkMNAOwlNX0EqoRQbmWWrgxTFL3ct7/wQCM                         
-----END CERTIFICATE-----`

	// Certificate:
	// Data:
	//     Version: 3 (0x2)
	//     Serial Number: 1512556025483463 (0x55fa9649a10c7)
	//     Signature Algorithm: sha256WithRSAEncryption
	//     Issuer: C = GB, ST = London, O = Google UK Ltd., OU = Certificate Transparency, CN = Merge Delay Intermediate 1
	//     Validity
	//         Not Before: Dec  6 10:27:05 2017 GMT
	//         Not After : Nov  6 14:27:14 2019 GMT
	//     Subject: C = GB, L = London, O = Google Certificate Transparency, serialNumber = 1512556025483463
	//     Subject Public Key Info:
	//         Public Key Algorithm: rsaEncryption
	//             RSA Public-Key: (2048 bit)
	//             Modulus:
	//                 00:af:14:04:af:91:5a:af:6c:54:91:c4:6a:ea:55:
	//                 6e:36:a8:5f:83:40:e9:f1:3f:cc:63:ea:a7:98:c0:
	//                 86:54:ac:e3:4e:62:c1:e8:b9:d6:65:ac:1f:97:dd:
	//                 2e:14:b6:e3:88:3a:6c:32:ca:4b:7a:bd:70:af:b7:
	//                 1f:b3:e4:f9:e5:61:44:46:51:cc:14:8d:64:b4:df:
	//                 bd:68:3c:ff:d1:33:75:d5:71:e3:02:8c:09:fc:32:
	//                 02:d8:53:70:c0:5c:53:90:b4:c3:63:51:92:0b:ae:
	//                 7f:c3:51:70:89:89:5e:df:07:35:b8:bf:9d:17:66:
	//                 41:bc:31:b8:fa:a8:0e:c2:c7:a3:40:a7:80:34:dc:
	//                 de:2f:eb:81:c2:46:95:76:b9:26:77:b7:ba:11:e3:
	//                 8a:0d:8e:f8:f3:df:8c:ec:bc:41:a1:2f:76:de:be:
	//                 50:c9:c5:c8:da:d1:3a:0c:20:44:8a:ff:2c:52:70:
	//                 56:eb:c3:02:54:3d:94:9b:05:23:45:24:b0:e4:66:
	//                 55:37:2c:ae:b3:2b:a1:bf:14:5c:ca:1b:d3:21:7d:
	//                 db:26:f7:6b:4b:57:de:06:56:4d:5d:b1:6f:3a:e4:
	//                 8c:b7:d6:b2:2f:29:46:f9:dc:3d:b5:34:55:49:e3:
	//                 c3:08:e5:c2:32:71:c0:fb:46:a6:9e:74:5c:3e:ef:
	//                 2c:2b
	//             Exponent: 65537 (0x10001)
	//     X509v3 extensions:
	//         X509v3 Extended Key Usage:
	//             TLS Web Server Authentication
	//         X509v3 Subject Alternative Name:
	//             DNS:flowers-to-the-world.com
	//         X509v3 Basic Constraints: critical
	//             CA:FALSE
	//         X509v3 Authority Key Identifier:
	//             keyid:E9:3C:04:E1:80:2F:C2:84:13:2D:26:70:9E:F2:FD:1A:CF:AA:FE:C6
	//
	//         X509v3 Subject Key Identifier:
	//             B3:8B:4A:FB:9B:7C:28:02:03:87:6B:DF:03:B7:E1:A0:1B:FE:61:F3
	// Signature Algorithm: sha256WithRSAEncryption
	//      6c:b1:ff:51:15:54:d3:e5:00:f4:76:21:9f:e3:63:07:7e:40:
	//      a7:b8:d3:14:1c:d3:35:37:e9:47:68:d4:d2:a4:7f:65:81:fc:
	//      da:eb:46:cd:97:8b:18:9a:d5:60:06:8d:80:0b:35:b6:33:89:
	//      69:04:37:00:ab:f1:07:2f:fc:69:83:f2:a2:1e:68:5c:81:92:
	//      af:be:f9:83:fa:25:7a:6b:9c:36:c7:17:a5:b7:7f:5f:9d:03:
	//      73:f4:a9:32:b1:2f:88:e4:82:a5:83:0a:be:b3:69:6b:bd:ed:
	//      89:55:33:cc:16:8e:c3:98:f4:a1:96:96:28:45:81:bb:e2:72:
	//      ac:12:20:18:d7:18:39:33:5c:7e:2f:6f:3b:c3:e4:20:94:fb:
	//      f1:47:51:92:89:40:2d:c8:96:22:52:41:9c:09:23:67:61:6e:
	//      ea:04:91:ca:2a:46:df:81:26:68:2e:32:17:52:3a:4e:43:06:
	//      c1:05:81:95:13:65:fd:2b:6f:81:d3:23:f4:08:f7:53:30:71:
	//      59:e7:d9:29:52:37:05:e6:c2:6d:8d:4b:f0:bf:13:ed:11:2c:
	//      db:6d:9a:13:d0:3f:93:36:73:5f:b6:3e:30:e7:03:ef:17:75:
	//      ec:84:71:dd:fe:db:16:d3:56:f0:d7:9c:49:cd:4f:5c:80:52:
	//      be:57:1d:71:a4:4d:f3:67:7b:cd:6f:a3:16:16:aa:67:28:f7:
	//      9e:88:3e:fc:2a:a2:75:c0:87:68:e0:3e:61:d5:d3:f6:6e:6e:
	//      56:1f:89:08:b8:48:38:5f:90:fe:2e:d9:f8:cf:b4:92:2d:5d:
	//      fe:99:92:4d:bc:89:59:29:2b:ea:9e:87:99:0d:9a:13:4e:c9:
	//      7a:7a:da:83:3a:36:3a:06:e8:0a:b9:be:1f:50:78:4e:75:32:
	//      dd:b8:f3:a6:31:7a:e5:c7:0d:80:29:c2:76:65:a4:aa:67:fe:
	//      bf:b9:be:04:1a:38:23:22:06:ce:6d:21:ce:cc:ee:6a:aa:d8:
	//      c8:05:bf:23:5f:0f:45:9e:cb:ee:22:30:2c:43:b3:fe:97:73:
	//      10:71:0a:d2:b4:68:e2:54:06:56:a9:27:dd:ae:20:e2:4a:3d:
	//      23:9c:c3:da:c6:9b:25:36:dc:b5:0b:ff:b9:0a:03:2c:f0:6c:
	//      c3:17:af:11:13:73:0a:d3:d7:10:39:af:25:7c:f9:58:68:7d:
	//      5d:6b:0b:89:3d:ec:82:8f:d0:5e:1b:bb:0b:d4:25:45:94:2b:
	//      3e:39:fc:c5:a2:76:b5:5d:bb:80:56:78:48:c2:27:61:13:73:
	//      46:b7:7d:4a:28:c7:c9:d4:28:9b:da:98:9a:06:b4:7d:ab:36:
	//      89:ec:be:db:35:00:c2:8a
	leafPEM = `-----BEGIN CERTIFICATE-----                                                      
MIIE7zCCAtegAwIBAgIHBV+pZJoQxzANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQG                 
EwJHQjEPMA0GA1UECAwGTG9uZG9uMRcwFQYDVQQKDA5Hb29nbGUgVUsgTHRkLjEh                 
MB8GA1UECwwYQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5MSMwIQYDVQQDDBpNZXJn                 
ZSBEZWxheSBJbnRlcm1lZGlhdGUgMTAeFw0xNzEyMDYxMDI3MDVaFw0xOTExMDYx                 
NDI3MTRaMGMxCzAJBgNVBAYTAkdCMQ8wDQYDVQQHDAZMb25kb24xKDAmBgNVBAoM                 
H0dvb2dsZSBDZXJ0aWZpY2F0ZSBUcmFuc3BhcmVuY3kxGTAXBgNVBAUTEDE1MTI1                 
NTYwMjU0ODM0NjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvFASv                 
kVqvbFSRxGrqVW42qF+DQOnxP8xj6qeYwIZUrONOYsHoudZlrB+X3S4UtuOIOmwy                 
ykt6vXCvtx+z5PnlYURGUcwUjWS0371oPP/RM3XVceMCjAn8MgLYU3DAXFOQtMNj                 
UZILrn/DUXCJiV7fBzW4v50XZkG8Mbj6qA7Cx6NAp4A03N4v64HCRpV2uSZ3t7oR                 
44oNjvjz34zsvEGhL3bevlDJxcja0ToMIESK/yxScFbrwwJUPZSbBSNFJLDkZlU3                 
LK6zK6G/FFzKG9Mhfdsm92tLV94GVk1dsW865Iy31rIvKUb53D21NFVJ48MI5cIy                 
ccD7RqaedFw+7ywrAgMBAAGjgYswgYgwEwYDVR0lBAwwCgYIKwYBBQUHAwEwIwYD                 
VR0RBBwwGoIYZmxvd2Vycy10by10aGUtd29ybGQuY29tMAwGA1UdEwEB/wQCMAAw                 
HwYDVR0jBBgwFoAU6TwE4YAvwoQTLSZwnvL9Gs+q/sYwHQYDVR0OBBYEFLOLSvub                 
fCgCA4dr3wO34aAb/mHzMA0GCSqGSIb3DQEBCwUAA4ICAQBssf9RFVTT5QD0diGf                 
42MHfkCnuNMUHNM1N+lHaNTSpH9lgfza60bNl4sYmtVgBo2ACzW2M4lpBDcAq/EH                 
L/xpg/KiHmhcgZKvvvmD+iV6a5w2xxelt39fnQNz9KkysS+I5IKlgwq+s2lrve2J                 
VTPMFo7DmPShlpYoRYG74nKsEiAY1xg5M1x+L287w+QglPvxR1GSiUAtyJYiUkGc                 
CSNnYW7qBJHKKkbfgSZoLjIXUjpOQwbBBYGVE2X9K2+B0yP0CPdTMHFZ59kpUjcF                 
5sJtjUvwvxPtESzbbZoT0D+TNnNftj4w5wPvF3XshHHd/tsW01bw15xJzU9cgFK+                 
Vx1xpE3zZ3vNb6MWFqpnKPeeiD78KqJ1wIdo4D5h1dP2bm5WH4kIuEg4X5D+Ltn4                 
z7SSLV3+mZJNvIlZKSvqnoeZDZoTTsl6etqDOjY6BugKub4fUHhOdTLduPOmMXrl                 
xw2AKcJ2ZaSqZ/6/ub4EGjgjIgbObSHOzO5qqtjIBb8jXw9FnsvuIjAsQ7P+l3MQ                 
cQrStGjiVAZWqSfdriDiSj0jnMPaxpslNty1C/+5CgMs8GzDF68RE3MK09cQOa8l                 
fPlYaH1dawuJPeyCj9BeG7sL1CVFlCs+OfzFona1XbuAVnhIwidhE3NGt31KKMfJ                 
1Cib2piaBrR9qzaJ7L7bNQDCig==                                                     
-----END CERTIFICATE-----`

	sct = `{"sct_version":0,"id":"CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=","timestamp":1512556025588,"extensions":"","signature":"BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="}`

	leafHash        = "uvjbEw+porcnNLYkXBSVecJdl7QfuL4SAwZZWobcwHg="
	treeSize uint64 = 30

	getProofByHashRespBody = `{"leaf_index":10,"audit_path":["pWAVPaJIQdVdHgm/GWo/tf0a0gaG4JjCanqHc49kxpU=","+05OCiIkipWWDKhByJGctdwLiSo1geIvWF8pDGv2VFw=","aBTbMciBy2Ey35az07wjEiFN1kWn+37LVa07BQCH2qo=","t+sKhOFhVnTT/6bmOSyVWKfGagwJBVvcyynO2oJLxsY=","LRdkcLMeof0FdRmX6IVaDTITWJUr8eABhUaHa0vcWNw="]}`
)

func TestGetProofByHash(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		statusCode   int
		body         []byte
		wantErrType  reflect.Type
		wantResponse *ct.GetProofByHashResponse
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
			body:       []byte(getProofByHashRespBody),
			wantResponse: &ct.GetProofByHashResponse{
				LeafIndex: 10,
				AuditPath: [][]byte{
					mustB64Decode("pWAVPaJIQdVdHgm/GWo/tf0a0gaG4JjCanqHc49kxpU="),
					mustB64Decode("+05OCiIkipWWDKhByJGctdwLiSo1geIvWF8pDGv2VFw="),
					mustB64Decode("aBTbMciBy2Ey35az07wjEiFN1kWn+37LVa07BQCH2qo="),
					mustB64Decode("t+sKhOFhVnTT/6bmOSyVWKfGagwJBVvcyynO2oJLxsY="),
					mustB64Decode("LRdkcLMeof0FdRmX6IVaDTITWJUr8eABhUaHa0vcWNw="),
				},
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

			gotResp, gotHTTPData, gotErr := lc.GetProofByHash(mustB64Decode(leafHash), treeSize)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("GetProofByHash(%s, %d): error was of type %v, want %v", leafHash, treeSize, gotErrType, test.wantErrType)
			}
			if gotHTTPData == nil {
				t.Fatalf("GetProofByHash(%s, %d) = (_, nil, _), want an HTTPData containing at least the timing of the request", leafHash, treeSize)
			}
			if gotHTTPData.Timing.Start.IsZero() || gotHTTPData.Timing.End.IsZero() {
				t.Errorf("GetProofByHash(%s, %d): HTTPData.Timing = %+v, want the Timing to be populated with the timing of the request", leafHash, treeSize, gotHTTPData.Timing)
			}
			if !bytes.Equal(gotHTTPData.Body, test.body) {
				t.Errorf("GetProofByHash(%s, %d): HTTPData.Body = %s, want %s", leafHash, treeSize, gotHTTPData.Body, test.body)
			}

			if gotErr != nil {
				return
			}

			if diff := cmp.Diff(gotResp, test.wantResponse); diff != "" {
				t.Errorf("GetProofByHash(%s, %d): ct.GetProofByHashResponse diff: (-got +want)\n%s", leafHash, treeSize, diff)
			}
		})
	}
}

// TODO(katjoyce): Improve these tests - try to find a way to test for all error
// types that could be returned by Post.
func TestPost(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		statusCode  int
		rspBody     []byte
		wantErrType reflect.Type
	}{
		{
			name:        "post error",
			url:         "not-a-real-url",
			wantErrType: reflect.TypeOf(&PostError{}),
		},
		{
			name:        "HTTP status error",
			statusCode:  http.StatusNotFound,
			wantErrType: reflect.TypeOf(&HTTPStatusError{}),
		},
		{
			name:       "no error",
			statusCode: http.StatusOK,
			rspBody:    []byte(sct),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeServer(test.statusCode, test.rspBody)
			lc := New(s.URL, &http.Client{})
			if test.url != "" {
				lc = New(test.url, &http.Client{})
			}

			got, gotErr := lc.post("", nil)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("Post(_, _): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if got == nil {
				t.Fatal("Post(_, _) = nil, _, want an HTTPData containing at least the timing of the request")
			}
			if got.Timing.Start.IsZero() || got.Timing.End.IsZero() {
				t.Errorf("Post(_, _): HTTPData.Timing = %+v, want the Timing to be populated with the timing of the request", got.Timing)
			}
			if !bytes.Equal(got.Body, test.rspBody) {
				t.Errorf("Post(_, _): HTTPData.Body = %s, want %s", got.Body, test.rspBody)
			}
		})
	}
}

func TestPostAndParse(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		statusCode  int
		rspBody     []byte
		wantErrType reflect.Type
	}{
		{
			name:        "get error",
			url:         "not-a-real-url",
			wantErrType: reflect.TypeOf(&PostError{}),
		},
		{
			name:        "HTTP status error",
			statusCode:  http.StatusNotFound,
			wantErrType: reflect.TypeOf(&HTTPStatusError{}),
		},
		{
			name:        "JSON Parse Error",
			statusCode:  http.StatusOK,
			rspBody:     []byte("not-valid-json"),
			wantErrType: reflect.TypeOf(&JSONParseError{}),
		},
		{
			name:       "no error",
			statusCode: http.StatusOK,
			rspBody:    []byte(sct),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeServer(test.statusCode, test.rspBody)
			lc := New(s.URL, &http.Client{})
			if test.url != "" {
				lc = New(test.url, &http.Client{})
			}

			var resp ct.AddChainResponse
			got, gotErr := lc.postAndParse("", nil, &resp)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("PostAndParse(_, _): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if got == nil {
				t.Fatal("PostAndParse(_, _) = nil, _, want an HTTPData containing at least the timing of the request")
			}
			if got.Timing.Start.IsZero() || got.Timing.End.IsZero() {
				t.Errorf("PostAndParse(_, _): HTTPData.Timing = %+v, want the Timing to be populated with the timing of the request", got.Timing)
			}
			if !bytes.Equal(got.Body, test.rspBody) {
				t.Errorf("PostAndParse(_, _): HTTPData.Body = %s, want %s", got.Body, test.rspBody)
			}
		})
	}
}

func createChain(t *testing.T, pemChain []string) []*x509.Certificate {
	t.Helper()
	var chain []*x509.Certificate
	for _, pc := range pemChain {
		cert, err := x509util.CertificateFromPEM([]byte(pc))
		if err != nil {
			t.Fatalf("Unable to parse from PEM to *x509.Certificate: %s", err)
		}
		chain = append(chain, cert)
	}
	return chain
}

func TestAddChain(t *testing.T) {
	var (
		sctMissingID        = `{"sct_version":0,"timestamp":1512556025588,"extensions":"","signature":"BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="}`
		sctMissingTimestamp = `{"sct_version":0,"id":"CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=","extensions":"","signature":"BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="}`
		sctMissingSig       = `{"sct_version":0,"id":"CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=","timestamp":1512556025588,"extensions":""}`
	)

	tests := []struct {
		name        string
		url         string
		statusCode  int
		rspBody     []byte
		wantErrType reflect.Type
		wantSCT     *ct.AddChainResponse
	}{
		{
			name:        "get error",
			url:         "not-a-real-url",
			wantErrType: reflect.TypeOf(&PostError{}),
		},
		{
			name:        "HTTP status error",
			statusCode:  http.StatusNotFound,
			wantErrType: reflect.TypeOf(&HTTPStatusError{}),
		},
		{
			name:        "JSON Parse Error",
			statusCode:  http.StatusOK,
			rspBody:     []byte("not-valid-json"),
			wantErrType: reflect.TypeOf(&JSONParseError{}),
		},
		{
			name:        "SCT missing Log ID",
			statusCode:  http.StatusOK,
			rspBody:     []byte(sctMissingID),
			wantErrType: reflect.TypeOf(&ResponseToStructError{}),
		},
		{
			// TODO(katjoyce): Return error for missing timestamp
			name:       "SCT missing Timestamp",
			statusCode: http.StatusOK,
			rspBody:    []byte(sctMissingTimestamp),
			wantSCT: &ct.AddChainResponse{
				ID:        mustB64Decode("CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA="),
				Timestamp: 0,
				Signature: mustB64Decode("BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="),
			},
		},
		{
			name:        "SCT missing Signature",
			statusCode:  http.StatusOK,
			rspBody:     []byte(sctMissingSig),
			wantErrType: reflect.TypeOf(&ResponseToStructError{}),
		},
		{
			name:       "no error",
			statusCode: http.StatusOK,
			rspBody:    []byte(sct),
			wantSCT: &ct.AddChainResponse{
				ID:        mustB64Decode("CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA="),
				Timestamp: 1512556025588,
				Signature: mustB64Decode("BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="),
			},
		},
	}

	chain := createChain(t, []string{leafPEM, intermediatePEM, rootPEM})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeServer(test.statusCode, test.rspBody)
			lc := New(s.URL, &http.Client{})
			if test.url != "" {
				lc = New(test.url, &http.Client{})
			}

			gotSCT, gotHTTPData, gotErr := lc.addChain(ct.AddChainPath, chain)
			if gotErrType := reflect.TypeOf(gotErr); gotErrType != test.wantErrType {
				t.Errorf("AddChain(): error was of type %v, want %v", gotErrType, test.wantErrType)
			}
			if gotHTTPData == nil {
				t.Fatal("AddChain() = (_, nil, _), want an HTTPData containing at least the timing of the request")
			}
			if gotHTTPData.Timing.Start.IsZero() || gotHTTPData.Timing.End.IsZero() {
				t.Errorf("AddChain(): HTTPData.Timing = %+v, want the Timing to be populated with the timing of the request", gotHTTPData.Timing)
			}
			if !bytes.Equal(gotHTTPData.Body, test.rspBody) {
				t.Errorf("AddChain(): HTTPData.Body = %s, want %s", gotHTTPData.Body, test.rspBody)
			}

			if gotErr != nil {
				return
			}

			want, err := test.wantSCT.ToSignedCertificateTimestamp()
			if err != nil {
				t.Fatalf("ct.AddChainResponse.ToSignedCertificateTimestamp(): %s", err)
			}
			if diff := cmp.Diff(gotSCT, want); diff != "" {
				t.Errorf("AddChain(): ct.SignedCertificateTimestamp diff: (-got +want)\n%s", diff)
			}
		})
	}
}
