package attest_test

import (
	"context"
	"errors"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kanywst/omega/internal/server/attest"
)

// makeFakeClient builds a fake clientset that intercepts every
// `TokenReviews.Create` and returns the provided response, so tests
// can exercise the success and failure branches without standing up
// a kube-apiserver.
func makeFakeClient(t *testing.T, resp authnv1.TokenReviewStatus, callErr error) *fake.Clientset {
	t.Helper()
	c := fake.NewSimpleClientset()
	c.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if callErr != nil {
			return true, nil, callErr
		}
		tr := action.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		tr.Status = resp
		return true, tr, nil
	})
	return c
}

func TestAttestSucceedsForServiceAccountToken(t *testing.T) {
	client := makeFakeClient(t, authnv1.TokenReviewStatus{
		Authenticated: true,
		User: authnv1.UserInfo{
			Username: "system:serviceaccount:apps:web",
			Extra: map[string]authnv1.ExtraValue{
				"authentication.kubernetes.io/pod-name": {"web-7b9f6d6c-abcde"},
			},
		},
		Audiences: []string{"omega.local"},
	}, nil)

	a := attest.NewK8sAttestor(client, []string{"omega.local"})
	claims, err := a.Attest(context.Background(), "fake.jwt.token")
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if claims.Namespace != "apps" || claims.ServiceAccount != "web" {
		t.Errorf("ns/sa: got %q/%q want apps/web", claims.Namespace, claims.ServiceAccount)
	}
	if claims.PodName != "web-7b9f6d6c-abcde" {
		t.Errorf("pod: got %q", claims.PodName)
	}
	if len(claims.Audiences) != 1 || claims.Audiences[0] != "omega.local" {
		t.Errorf("audiences: %v", claims.Audiences)
	}
}

func TestAttestRejectsEmptyToken(t *testing.T) {
	a := attest.NewK8sAttestor(makeFakeClient(t, authnv1.TokenReviewStatus{}, nil), nil)
	if _, err := a.Attest(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestAttestRejectsUnauthenticated(t *testing.T) {
	client := makeFakeClient(t, authnv1.TokenReviewStatus{
		Authenticated: false,
		Error:         "token expired",
	}, nil)
	a := attest.NewK8sAttestor(client, nil)
	if _, err := a.Attest(context.Background(), "x.y.z"); err == nil {
		t.Fatal("expected error for unauthenticated token")
	}
}

func TestAttestRejectsNonServiceAccountUser(t *testing.T) {
	client := makeFakeClient(t, authnv1.TokenReviewStatus{
		Authenticated: true,
		User:          authnv1.UserInfo{Username: "system:kube-controller-manager"},
	}, nil)
	a := attest.NewK8sAttestor(client, nil)
	if _, err := a.Attest(context.Background(), "x.y.z"); err == nil {
		t.Fatal("expected error for non-SA user")
	}
}

func TestAttestPropagatesTokenReviewErrors(t *testing.T) {
	client := makeFakeClient(t, authnv1.TokenReviewStatus{}, errors.New("apiserver unreachable"))
	a := attest.NewK8sAttestor(client, nil)
	_, err := a.Attest(context.Background(), "x.y.z")
	if err == nil {
		t.Fatal("expected propagated apiserver error")
	}
	if errors.Is(err, attest.ErrTokenRejected) {
		t.Fatalf("apiserver-side failure must NOT match ErrTokenRejected: %v", err)
	}
}

// All four token-validation failure paths must surface as
// ErrTokenRejected so the HTTP layer can answer 401 vs 502 and only
// audit the former as a deny.
func TestAttestRejectionsAreErrTokenRejected(t *testing.T) {
	cases := []struct {
		name   string
		status authnv1.TokenReviewStatus
		token  string
	}{
		{"empty token", authnv1.TokenReviewStatus{}, ""},
		{"unauthenticated", authnv1.TokenReviewStatus{Authenticated: false, Error: "expired"}, "x.y.z"},
		{"non-SA user", authnv1.TokenReviewStatus{
			Authenticated: true,
			User:          authnv1.UserInfo{Username: "system:kube-controller-manager"},
		}, "x.y.z"},
		{"malformed SA user", authnv1.TokenReviewStatus{
			Authenticated: true,
			User:          authnv1.UserInfo{Username: "system:serviceaccount:onlyone"},
		}, "x.y.z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := attest.NewK8sAttestor(makeFakeClient(t, tc.status, nil), nil)
			_, err := a.Attest(context.Background(), tc.token)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, attest.ErrTokenRejected) {
				t.Fatalf("error must match ErrTokenRejected, got: %v", err)
			}
		})
	}
}

func TestRenderSPIFFEIDExpandsAllPlaceholders(t *testing.T) {
	got, err := attest.RenderSPIFFEID(
		"spiffe://omega.local/k8s/{namespace}/{serviceaccount}/{podname}",
		&attest.K8sClaims{Namespace: "apps", ServiceAccount: "web", PodName: "web-abcde"},
	)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := "spiffe://omega.local/k8s/apps/web/web-abcde"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRenderSPIFFEIDRejectsPodNameTemplateWithoutPodName(t *testing.T) {
	_, err := attest.RenderSPIFFEID(
		"spiffe://omega.local/k8s/{namespace}/{serviceaccount}/{podname}",
		&attest.K8sClaims{Namespace: "apps", ServiceAccount: "web"},
	)
	if err == nil {
		t.Fatal("expected error for {podname} with empty PodName")
	}
}

func TestRenderSPIFFEIDPodNameOptional(t *testing.T) {
	got, err := attest.RenderSPIFFEID(
		"spiffe://omega.local/k8s/{namespace}/{serviceaccount}",
		&attest.K8sClaims{Namespace: "apps", ServiceAccount: "web"},
	)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != "spiffe://omega.local/k8s/apps/web" {
		t.Fatalf("got %q", got)
	}
}
