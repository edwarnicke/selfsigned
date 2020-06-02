package selfsigned

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"

	"github.com/cloudflare/cfssl/signer"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// X509TemplateFunc - Function for generating an X509 Template
type X509TemplateFunc func(publicKey crypto.PublicKey) (*x509.Certificate, error)

// X509CATemplate - X509 Template for a CA
func X509CATemplate(publicKey crypto.PublicKey) (*x509.Certificate, error) {
	// Borrowed with love from https://github.com/spiffe/spire/blob/a5b56f820d5d31de074e5e63ec90261b391dab19/pkg/server/ca/templates.go#L15
	subject := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating newSelfSignedX509Source")
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		URIs:         []*url.URL{spiffeid.Must(trustDomain, uuid.New().String()).URL()},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             publicKey,
	}
	template.SubjectKeyId, err = signer.ComputeSKI(template)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating X509CATemplate")
	}
	return template, nil
}

// X509SVIDTemplate - returns a template for an X509SVID certificate for the provided spiffeID, publicKey, notBefore, notAfter,and serialNumber
func X509SVIDTemplate(publicKey crypto.PublicKey) (*x509.Certificate, error) {
	// Borrowed with love and adapted from https://github.com/spiffe/spire/blob/248127372308a5542a62bb344422d6a2061530b0/pkg/server/ca/templates.go#L42
	// Under that Apache 2.0 License: https://github.com/spiffe/spire/blob/master/LICENSE

	subject := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating newSelfSignedX509Source")
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		URIs:         []*url.URL{spiffeid.Must(trustDomain, uuid.New().String()).URL()},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		PublicKey:             publicKey,
	}

	template.SubjectKeyId, err = signer.ComputeSKI(template)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating X509SVIDTemplate")
	}

	return template, nil
}
