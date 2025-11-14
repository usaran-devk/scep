package executablesigner

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/go-kit/log"
	"github.com/smallstep/scep"
	scepserver "github.com/usaran-devk/scep/v2/server"
)

const (
	userExecute os.FileMode = 1 << (6 - 3*iota)
	groupExecute
	otherExecute
	cmdSign             = "sign"
	cmdCACert           = "cacert"
	cmdCACaps           = "cacaps"
	defaultValidityDays = 30
)

// New creates a executablesigner.ExecutableSigner.
func New(path string, logger log.Logger, opts ...Option) (*ExecutableSigner, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileMode := fileInfo.Mode()
	if fileMode.IsDir() {
		return nil, errors.New("CSR Verifier executable is a directory")
	}

	filePerm := fileMode.Perm()
	if filePerm&(userExecute|groupExecute|otherExecute) == 0 {
		return nil, errors.New("CSR Verifier executable is not executable")
	}

	s := &ExecutableSigner{
		executable:   path,
		logger:       logger,
		validityDays: defaultValidityDays,
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

type ExecutableSigner struct {
	executable   string
	validityDays int
	logger       log.Logger
}

// Option customizes ExecutableSigner
type Option func(*ExecutableSigner) error

// SignCSR signs a certificate using an external command
// The first argument is "sign"
// The CSR is passed as PEM data on stdin
// The challenge password is passed as environment variable SCEP_CHALLENGE_PASSWORD
// The signed certificate is expected on stdout as PEM data
func (s *ExecutableSigner) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {
	var out bytes.Buffer

	cmd := exec.Command(s.executable, cmdSign)
	cmd.Env = append(os.Environ(),
		"SCEP_CHALLENGE_PASSWORD="+m.ChallengePassword,
		fmt.Sprintf("CERT_VALIDITY_DAYS=%d", s.validityDays),
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = &out

	csrDerBytes := m.CSR.Raw
	csrPemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDerBytes})
	go func() {
		defer stdin.Close()

		stdin.Write(csrPemData)
	}()

	err = cmd.Run()
	if err != nil {
		s.logger.Log("err", err)
		return nil, err
	}

	certPemData := out.String()
	// fmt.Println("Captured PEM Data:\n", pemData)

	// Decode the PEM
	block, _ := pem.Decode([]byte(certPemData))
	if block == nil || block.Type != "CERTIFICATE" {
		err := fmt.Errorf("Failed to decode PEM block containing the certificate")
		s.logger.Log("err", err)
		return nil, err
	}

	return x509.ParseCertificate(block.Bytes)
}

// CACert returns the CA certificate chain
// The first argument is "cacert"
// The ca certificate chain is expected on stdout as PEM data
func (s *ExecutableSigner) CACert() ([]*x509.Certificate, error) {
	var out bytes.Buffer

	cmd := exec.Command(s.executable, cmdCACert)
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		s.logger.Log("err", err)
		return nil, err
	}

	certPemData := out.Bytes()
	// fmt.Println("Captured PEM Data:\n", pemData)

	// Decode the PEM
	var cacerts []*x509.Certificate

	for {
		block, rest := pem.Decode(certPemData)
		if block == nil {
			break // No more PEM blocks to decode
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				err := fmt.Errorf("Failed to decode PEM block containing the certificate: %v", err)
				s.logger.Log("err", err)
				return nil, err
			}
			cacerts = append(cacerts, cert)
		}

		certPemData = rest
	}

	return cacerts, nil
}

// CACaps returns the CA capabilities
func (s *ExecutableSigner) CACaps() (*scepserver.CSRSignerCACaps, error) {
	var out bytes.Buffer

	cmd := exec.Command(s.executable, cmdCACaps)
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		s.logger.Log("err", err)
		return nil, err
	}

	c, err := strconv.Atoi(strings.Split(out.String(), "\n")[0])
	if err != nil {
		s.logger.Log("err", err)
		return nil, err
	}
	return scepserver.NewCSRSignerCACaps(scepserver.CSRSignerCACaps(c))
}

// WithValidityDays sets the validity period new certs will use
func WithValidityDays(v int) Option {
	return func(s *ExecutableSigner) error {
		if v <= 0 {
			return fmt.Errorf("validity days must be >= 1")
		}
		s.validityDays = v

		return nil
	}
}
