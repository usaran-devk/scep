package scepserver

import (
	"context"
	"testing"

	"github.com/smallstep/scep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChallengeMiddleware(t *testing.T) {
	testPW := "RIGHT"
	signer := StaticChallengeMiddleware(testPW, NopCSRSigner())

	csrReq := &scep.CSRReqMessage{ChallengePassword: testPW}

	ctx := context.Background()

	_, err := signer.SignCSRContext(ctx, csrReq)
	if err != nil {
		t.Error(err)
	}

	csrReq.ChallengePassword = "WRONG"

	_, err = signer.SignCSRContext(ctx, csrReq)
	if err == nil {
		t.Error("invalid challenge should generate an error")
	}
}

func TestNewCSRSignerCACaps(t *testing.T) {
	caps, err := NewCSRSignerCACaps(CSRSignerCACaps(0))
	assert.NoError(t, err)
	assert.NotNil(t, caps)

	caps, err = NewCSRSignerCACaps(CSRSignerCACaps(1))
	assert.NoError(t, err)
	assert.NotNil(t, caps)

	caps, err = NewCSRSignerCACaps(CSRSignerCACaps(2))
	assert.Error(t, err)
	assert.Nil(t, caps)
}

func TestSCEPCACaps(t *testing.T) {
	caps, err := NewCSRSignerCACaps(CSRSignerCACaps(0))
	assert.NoError(t, err)
	require.NotNil(t, caps)
	scepcaps := caps.SCEPCACaps()
	expectedScapCaps := []byte{}
	assert.Equal(t, expectedScapCaps, scepcaps)

	caps, err = NewCSRSignerCACaps(CSRSignerCACaps(1))
	assert.NoError(t, err)
	require.NotNil(t, caps)
	scepcaps = caps.SCEPCACaps()
	expectedScapCaps = []byte("Renewal\n")
	assert.Equal(t, expectedScapCaps, scepcaps)
}
