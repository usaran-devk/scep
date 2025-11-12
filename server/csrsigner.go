package scepserver

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"

	"github.com/smallstep/scep"
)

// CSRSignerContext is a handler for signing CSRs by a CA/RA.
//
// SignCSRContext should take the CSR in the CSRReqMessage and return a
// Certificate signed by the CA.
type CSRSignerContext interface {
	SignCSRContext(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error)
	CACertContext(context.Context) ([]*x509.Certificate, error)
}

// CSRSignerContextFunc is an adapter for CSR signing by the CA/RA.
type CSRSignerContextFunc struct {
	Sign   func(context.Context, *scep.CSRReqMessage) (*x509.Certificate, error)
	CAcert func(context.Context) ([]*x509.Certificate, error)
}

// SignCSR calls f.sign(ctx, m).
func (f CSRSignerContextFunc) SignCSRContext(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
	return f.Sign(ctx, m)
}

// CACert calls f.cacert(ctx, m).
func (f CSRSignerContextFunc) CACertContext(ctx context.Context) ([]*x509.Certificate, error) {
	return f.CAcert(ctx)
}

// CSRSigner is a handler for CSR signing by the CA/RA
//
// SignCSR should take the CSR in the CSRReqMessage and return a
// Certificate signed by the CA.
type CSRSigner interface {
	SignCSR(*scep.CSRReqMessage) (*x509.Certificate, error)
	CACert() ([]*x509.Certificate, error)
}

// CSRSignerFunc is an adapter for CSR signing by the CA/RA.
type CSRSignerFunc struct {
	Sign   func(*scep.CSRReqMessage) (*x509.Certificate, error)
	CAcert func() ([]*x509.Certificate, error)
}

// SignCSR calls f.sign(m).
func (f CSRSignerFunc) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {
	return f.Sign(m)
}

// CACert calls f.cacert().
func (f CSRSignerFunc) CACert() ([]*x509.Certificate, error) {
	return f.CAcert()
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
	}
}
