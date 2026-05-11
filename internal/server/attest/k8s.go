// Package attest is the omega-server-side attestor plugin layer.
//
// The current implementation is a Kubernetes ServiceAccount projected
// token attestor. The workload presents a token whose audience matches
// the omega server, omega calls back to the cluster's kube-apiserver
// `TokenReview` API to validate it, and the resulting
// `(namespace, serviceaccount[, podname])` triple is mapped into a
// SPIFFE ID via a configurable template.
//
// This package deliberately depends only on `k8s.io/api/authentication/v1`
// and the `kubernetes.Interface` client, so a fake client suffices for
// tests and a future second backend (EC2 IMDS, GCP IAM, etc.) can sit
// next to the K8sAttestor without dragging the K8s deps into other
// callers.
package attest

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// K8sClaims is the subset of a TokenReview response that survives the
// `(ns, sa[, pod])` projection. Audiences is what kube-apiserver
// returned, useful for audit context; SPIFFE ID derivation uses only
// Namespace / ServiceAccount / PodName.
type K8sClaims struct {
	Namespace      string
	ServiceAccount string
	PodName        string
	Audiences      []string
}

// K8sAttestor validates a Kubernetes ServiceAccount projected token
// against kube-apiserver. Audiences, when non-empty, is the expected
// `aud` set: TokenReview will reject the token if it was issued for a
// different audience. Empty disables the audience check (the default
// SA token has no audience constraint and matches anything).
type K8sAttestor struct {
	client    kubernetes.Interface
	audiences []string
}

// NewK8sAttestor wires the TokenReview client. The audience slice is
// copied so callers can mutate theirs without affecting the attestor.
func NewK8sAttestor(client kubernetes.Interface, audiences []string) *K8sAttestor {
	if client == nil {
		return nil
	}
	cp := append([]string(nil), audiences...)
	return &K8sAttestor{client: client, audiences: cp}
}

// Attest performs the TokenReview call and projects the authenticated
// user onto a K8sClaims. Returns a non-nil error when the token is
// empty, the apiserver rejects it, or the resulting user is not a
// service-account token (`system:serviceaccount:<ns>:<sa>`).
func (a *K8sAttestor) Attest(ctx context.Context, token string) (*K8sClaims, error) {
	if a == nil {
		return nil, errors.New("k8s attest: attestor is nil (not configured)")
	}
	if token == "" {
		return nil, errors.New("k8s attest: token is empty")
	}
	review := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token:     token,
			Audiences: a.audiences,
		},
	}
	out, err := a.client.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s attest: tokenreview: %w", err)
	}
	if !out.Status.Authenticated {
		msg := out.Status.Error
		if msg == "" {
			msg = "token rejected by kube-apiserver"
		}
		return nil, fmt.Errorf("k8s attest: %s", msg)
	}
	username := out.Status.User.Username
	const saPrefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, saPrefix) {
		return nil, fmt.Errorf("k8s attest: not a service-account token (user=%q)", username)
	}
	rest := strings.TrimPrefix(username, saPrefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("k8s attest: malformed service-account user %q", username)
	}
	claims := &K8sClaims{
		Namespace:      parts[0],
		ServiceAccount: parts[1],
		Audiences:      out.Status.Audiences,
	}
	// Pod name rides on the projected token via this stable extra
	// claim, present whenever the SA volume projection was created
	// with `serviceAccountToken.path = token` (the standard case).
	// Older clusters or non-projected tokens simply omit it.
	if extra, ok := out.Status.User.Extra["authentication.kubernetes.io/pod-name"]; ok && len(extra) > 0 {
		claims.PodName = extra[0]
	}
	return claims, nil
}

// RenderSPIFFEID interpolates `{namespace}`, `{serviceaccount}`, and
// `{podname}` placeholders in template using the values from c. Using
// `{podname}` is allowed only when the claims include one; missing
// pod-name is a hard error so the caller fails fast instead of
// producing a SPIFFE ID with a literal `{podname}` substring.
func RenderSPIFFEID(template string, c *K8sClaims) (string, error) {
	if c == nil {
		return "", errors.New("k8s attest: claims are nil")
	}
	if strings.Contains(template, "{podname}") && c.PodName == "" {
		return "", errors.New("k8s attest: template uses {podname} but the projected token has no pod-name extra claim")
	}
	s := template
	s = strings.ReplaceAll(s, "{namespace}", c.Namespace)
	s = strings.ReplaceAll(s, "{serviceaccount}", c.ServiceAccount)
	s = strings.ReplaceAll(s, "{podname}", c.PodName)
	return s, nil
}
