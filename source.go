// Copyright (c) 2020 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package selfsigned

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// X509Source - combination of x509svid.Source and x509bundle.Source
type X509Source interface {
	x509svid.Source
	x509bundle.Source
}

type x509Source struct {
	*x509svid.SVID
	*x509bundle.Bundle
}

// NewX509Source creates a new self signed X509Source.
func NewX509Source(ctx context.Context) (X509Source, error) {
	parentCert, parentPrivKey, err := newCert(X509CATemplate, nil, nil)
	if err != nil {
		return nil, err
	}
	parentID, err := x509svid.IDFromCert(parentCert)
	if err != nil {
		return nil, err
	}

	// Create bundle
	bundle := x509bundle.FromX509Authorities(parentID.TrustDomain(), []*x509.Certificate{parentCert})
	if err != nil {
		return nil, err
	}

	// Create SVID
	svid, err := newSVID(X509SVIDTemplate, parentCert, parentPrivKey)
	if err != nil {
		return nil, err
	}

	return &x509Source{
		SVID:   svid,
		Bundle: bundle,
	}, nil
}
