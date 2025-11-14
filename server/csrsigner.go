package scepserver

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"

	"github.com/smallstep/scep"
)

// CSRSignerCACaps defines the CA capabilities of a CSRSigner or CSRSignerContext type
// Currently, only the Renew capability is implemented
type CSRSignerCACaps int

const (
	// CSRSignerCACapsRenew specifies if a Cert Renew operation is supported by the Signer CA
	CSRSignerCACapsRenew CSRSignerCACaps = 1 << iota
)

// CSRSignerContext is a handler for signing CSRs by a CA/RA.
//
// SignCSRContext should take the CSR in the CSRReqMessage and return a
// Certificate signed by the CA.
type CSRSignerContext interface {
	SignCSRContext(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error)
	CACertContext(context.Context) ([]*x509.Certificate, error)
	CACapsContext(context.Context) (*CSRSignerCACaps, error)
}

// CSRSignerContextFunc is an adapter for CSR signing by the CA/RA.
type CSRSignerContextFunc struct {
	Sign   func(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error)
	CAcert func(context.Context) ([]*x509.Certificate, error)
	CAcaps func(context.Context) (*CSRSignerCACaps, error)
}

// SignCSR calls f.sign(ctx, m).
func (f CSRSignerContextFunc) SignCSRContext(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
	return f.Sign(ctx, m)
}

// CACert calls f.cacert(ctx, m).
func (f CSRSignerContextFunc) CACertContext(ctx context.Context) ([]*x509.Certificate, error) {
	return f.CAcert(ctx)
}

// CACaps calls f.cacaps(ctx, m).
func (f CSRSignerContextFunc) CACapsContext(ctx context.Context) (*CSRSignerCACaps, error) {
	return f.CAcaps(ctx)
}

// CSRSigner is a handler for CSR signing by the CA/RA
//
// SignCSR should take the CSR in the CSRReqMessage and return a
// Certificate signed by the CA.
type CSRSigner interface {
	SignCSR(*scep.CSRReqMessage) (*x509.Certificate, error)
	CACert() ([]*x509.Certificate, error)
	CACaps() (*CSRSignerCACaps, error)
}

// CSRSignerFunc is an adapter for CSR signing by the CA/RA.
type CSRSignerFunc struct {
	Sign   func(*scep.CSRReqMessage) (*x509.Certificate, error)
	CAcert func() ([]*x509.Certificate, error)
	CAcaps func() (*CSRSignerCACaps, error)
}

// NewCSRSignerCACaps creates a CSRSignerCACaps object and initializes it with the provided value
func NewCSRSignerCACaps(caps CSRSignerCACaps) (*CSRSignerCACaps, error) {
	// TODO: Find better way to check the valid range for caps value
	if caps < 0 {
		return nil, errors.New("csr signer ca caps value must not be negative")
	}
	if caps > 1 {
		return nil, errors.New("invalid csr signer ca caps value")
	}
	return &caps, nil
}

// SCEPCACaps returns the signer CA capabilities in the SCEP format
func (c *CSRSignerCACaps) SCEPCACaps() []byte {
	cacaps := []byte{}

	if *c&CSRSignerCACapsRenew == CSRSignerCACapsRenew {
		cacaps = append(cacaps, []byte("Renewal\n")...)
	}

	return cacaps
}

// SignCSR calls f.sign(m).
func (f CSRSignerFunc) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {
	return f.Sign(m)
}

// CACert calls f.cacert().
func (f CSRSignerFunc) CACert() ([]*x509.Certificate, error) {
	return f.CAcert()
}

// CACaps calls f.cacert().
func (f CSRSignerFunc) CACaps() (*CSRSignerCACaps, error) {
	return f.CAcaps()
}

// NopCSRSigner does nothing.
func NopCSRSigner() CSRSignerContextFunc {
	return CSRSignerContextFunc{
		Sign: func(_ context.Context, _ *scep.CSRReqMessage) (*x509.Certificate, error) {
			return nil, nil
		},
		CAcert: func(_ context.Context) ([]*x509.Certificate, error) {
			return nil, nil
		},
		CAcaps: func(_ context.Context) (*CSRSignerCACaps, error) {
			return NewCSRSignerCACaps(0)
		},
	}
}

// StaticChallengeMiddleware wraps next and validates the challenge from the CSR.
func StaticChallengeMiddleware(challenge string, next CSRSignerContext) CSRSignerContextFunc {
	challengeBytes := []byte(challenge)
	return CSRSignerContextFunc{
		Sign: func(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
			// TODO: compare challenge only for PKCSReq?
			if subtle.ConstantTimeCompare(challengeBytes, []byte(m.ChallengePassword)) != 1 {
				return nil, errors.New("invalid challenge")
			}
			return next.SignCSRContext(ctx, m)
		},
		CAcert: func(ctx context.Context) ([]*x509.Certificate, error) {
			return next.CACertContext(ctx)
		},
		CAcaps: func(ctx context.Context) (*CSRSignerCACaps, error) {
			return next.CACapsContext(ctx)
		},
	}
}

// SignCSRAdapter adapts a next (i.e. no context) to a context signer.
func SignCSRAdapter(next CSRSigner) CSRSignerContextFunc {
	return CSRSignerContextFunc{
		Sign: func(_ context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
			return next.SignCSR(m)
		},
		CAcert: func(_ context.Context) ([]*x509.Certificate, error) {
			return next.CACert()
		},
		CAcaps: func(_ context.Context) (*CSRSignerCACaps, error) {
			return next.CACaps()
		},
	}
}
