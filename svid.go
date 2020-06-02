package selfsigned

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	trustDomain = "selfsigned"
)

func newSVID(templateFunc X509TemplateFunc, parent *x509.Certificate, parentPrivKey crypto.PrivateKey) (*x509svid.SVID, error) {
	// Create cert
	cert, key, err := newCert(templateFunc, parent, parentPrivKey)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating newSelfSignedX509Source")
	}

	// Convert key to bytes
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating newSelfSignedX509Source")
	}

	// Create svid
	svid, err := x509svid.ParseRaw(cert.Raw, keyBytes)
	if err != nil {
		return nil, err
	}

	// Return source
	return svid, nil
}

func newCert(templateFunc X509TemplateFunc, parent *x509.Certificate, parentPrivKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	// Create private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error creating  SelfSigned X509 Cert")
	}

	// Create cert template
	template, err := templateFunc(key.Public())
	if err != nil {
		return nil, nil, err // Intentionally not Wrapping as done in called function
	}

	// Create cert
	if parent == nil {
		parent = template
		parentPrivKey = key
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error creating  SelfSigned X509 Cert")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error creating  SelfSigned X509 Cert")
	}
	return cert, key, nil
}
