// Copyright 2020 Google LLC
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

// Package testonly contains resources used during testing by multiple of the
// monologue packages.
package testonly

import (
	"encoding/base64"
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

func MustB64Decode(b64 string) []byte {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(err)
	}
	return b
}

func MustCreateChain(pemChain []string) []*x509.Certificate {
	var chain []*x509.Certificate
	for _, pc := range pemChain {
		cert, err := x509util.CertificateFromPEM([]byte(pc))
		if err != nil {
			panic(fmt.Errorf("unable to parse from PEM to *x509.Certificate: %s", err))
		}
		chain = append(chain, cert)
	}
	return chain
}
