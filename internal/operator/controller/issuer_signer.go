package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	cmissuerv1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"

	omegav1alpha1 "github.com/kanywst/omega/internal/operator/api/v1alpha1"
)

// IssuerSigner implements issuer-lib's Sign + Check by routing
// CertificateRequests to the Omega control plane's /v1/svid endpoint.
//
// The control plane is the source of truth for the SPIFFE identity
// shape: we only proxy the CSR to it and write the response back.
type IssuerSigner struct {
	HTTPClient *http.Client
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// Sign decodes the CSR, extracts a SPIFFE ID from the URI SAN, and asks
// Omega to sign it. Failure to find a SPIFFE-shaped URI SAN is a
// permanent error - re-signing the same CSR will keep failing.
func (s *IssuerSigner) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject cmissuerv1alpha1.Issuer) (signer.PEMBundle, error) {
	if s.HTTPClient == nil {
		s.HTTPClient = defaultHTTPClient()
	}
	url, err := s.issuerURL(issuerObject)
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: err}
	}

	details, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("decode certificate details: %w", err)}
	}

	spiffeID, err := extractSPIFFEID(details.CSR)
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: err}
	}

	body, err := json.Marshal(map[string]string{
		"spiffe_id": spiffeID,
		"csr":       string(details.CSR),
	})
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/v1/svid", bytes.NewReader(body))
	if err != nil {
		return signer.PEMBundle{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("POST %s/v1/svid: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		// 4xx are caller-side problems we should not silently retry
		// forever; anything else is a transient/server-side failure
		// and gets the standard issuer-lib retry budget.
		errMsg := fmt.Errorf("POST %s/v1/svid returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return signer.PEMBundle{}, signer.PermanentError{Err: errMsg}
		}
		return signer.PEMBundle{}, errMsg
	}

	var out struct {
		SVID   string `json:"svid"`
		Bundle string `json:"bundle"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return signer.PEMBundle{}, fmt.Errorf("decode /v1/svid response: %w", err)
	}
	if out.SVID == "" {
		return signer.PEMBundle{}, errors.New("/v1/svid returned empty svid PEM")
	}

	return signer.PEMBundle{
		ChainPEM: []byte(out.SVID),
		CAPEM:    []byte(out.Bundle),
	}, nil
}

// Check pings /v1/bundle to verify the control plane is reachable and
// has a usable trust bundle. Anything other than 200 with at least one
// certificate is reported as not-ready.
func (s *IssuerSigner) Check(ctx context.Context, issuerObject cmissuerv1alpha1.Issuer) error {
	if s.HTTPClient == nil {
		s.HTTPClient = defaultHTTPClient()
	}
	url, err := s.issuerURL(issuerObject)
	if err != nil {
		return signer.PermanentError{Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/v1/bundle", nil)
	if err != nil {
		return err
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s/v1/bundle: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s/v1/bundle returned %d", url, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if !bytes.Contains(raw, []byte("BEGIN CERTIFICATE")) {
		return fmt.Errorf("GET %s/v1/bundle returned no PEM certificate", url)
	}
	return nil
}

func (s *IssuerSigner) issuerURL(issuerObject cmissuerv1alpha1.Issuer) (string, error) {
	switch i := issuerObject.(type) {
	case *omegav1alpha1.OmegaIssuer:
		if i.Spec.URL == "" {
			return "", errors.New("OmegaIssuer.spec.url is required")
		}
		return strings.TrimRight(i.Spec.URL, "/"), nil
	case *omegav1alpha1.OmegaClusterIssuer:
		if i.Spec.URL == "" {
			return "", errors.New("OmegaClusterIssuer.spec.url is required")
		}
		return strings.TrimRight(i.Spec.URL, "/"), nil
	default:
		return "", fmt.Errorf("unexpected issuer type %T (only OmegaIssuer / OmegaClusterIssuer are supported)", issuerObject)
	}
}

func extractSPIFFEID(csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return "", errors.New("CSR is not PEM-encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse CSR: %w", err)
	}
	for _, u := range csr.URIs {
		if u.Scheme == "spiffe" {
			return u.String(), nil
		}
	}
	return "", errors.New("CSR has no spiffe:// URI SAN - set Certificate.spec.uris to a SPIFFE ID")
}
