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
