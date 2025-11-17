package csrsigner

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
	caps, err := NewCSRSignerCACaps()
	assert.NoError(t, err)
	assert.NotNil(t, caps)
	assert.Equal(t, 0, int(*caps))
}

func TestSCEPCACaps(t *testing.T) {
	caps := CSRSignerCACaps(0)
	scepcaps := caps.SCEPCACaps()
	expectedScapCaps := []byte{}
	assert.Equal(t, expectedScapCaps, scepcaps)

	caps = CSRSignerCACapsRenew
	scepcaps = caps.SCEPCACaps()
	expectedScapCaps = []byte("Renewal\n")
	assert.Equal(t, expectedScapCaps, scepcaps)
}

func TestWithRawValue(t *testing.T) {
	testCaps := 0
	caps, err := NewCSRSignerCACaps(WithRawValue(testCaps))
	assert.NoError(t, err)
	require.NotNil(t, caps)
	assert.Equal(t, testCaps, int(*caps))

	testCaps = int(CSRSignerCACapsRenew)
	caps, err = NewCSRSignerCACaps(WithRawValue(testCaps))
	assert.NoError(t, err)
	require.NotNil(t, caps)
	assert.Equal(t, testCaps, int(*caps))

	testCaps = int(CSRSignerCACapsAll)
	caps, err = NewCSRSignerCACaps(WithRawValue(testCaps))
	assert.NoError(t, err)
	require.NotNil(t, caps)
	assert.Equal(t, testCaps, int(*caps))

	testCaps = int(CSRSignerCACapsAll + 1)
	caps, err = NewCSRSignerCACaps(WithRawValue(testCaps))
	assert.Error(t, err)
	assert.Nil(t, caps)
}

func TestWithAllowCertRenewal(t *testing.T) {
	testCaps := CSRSignerCACapsRenew
	caps, err := NewCSRSignerCACaps(WithAllowCertRenewal())
	assert.NoError(t, err)
	require.NotNil(t, caps)
	assert.Equal(t, testCaps, *caps&CSRSignerCACapsRenew)
}

func TestHasCaps(t *testing.T) {
	for testCaps := 0; testCaps < 8; testCaps++ {
		caps := CSRSignerCACaps(testCaps)
		test := caps.HasCaps(CSRSignerCACapsRenew)
		if testCaps%2 == 0 {
			assert.False(t, test)
		} else {
			assert.True(t, test)
		}
	}
}
