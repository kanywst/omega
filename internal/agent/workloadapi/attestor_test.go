package workloadapi

import (
	"context"
	"errors"
	"net"
	"testing"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/kanywst/omega/internal/agent/attestor"
)

var errDenied = errors.New("denied")

type fakeAttestor struct {
	id  string
	ok  bool
	err error
	pid int32
}

func (f *fakeAttestor) Attest(_ context.Context, pid int32) (string, bool, error) {
	f.pid = pid
	return f.id, f.ok, f.err
}

func TestResolveWorkloadAttestorBeforeUIDMapping(t *testing.T) {
	mapping := Mapping{1000: "spiffe://omega.local/host/web"}
	creds := attestor.Creds{UID: 1000, PID: 4242}

	cases := []struct {
		name    string
		att     *fakeAttestor
		wantKey string
		wantID  string
		code    codes.Code
	}{
		{name: "pod workload", att: &fakeAttestor{id: "spiffe://omega.local/k8s/apps/web", ok: true}, wantKey: "id:spiffe://omega.local/k8s/apps/web", wantID: "spiffe://omega.local/k8s/apps/web"},
		{name: "host process falls through", att: &fakeAttestor{}, wantKey: "uid:1000", wantID: "spiffe://omega.local/host/web"},
		{name: "refused", att: &fakeAttestor{ok: true, err: errDenied}, code: codes.PermissionDenied},
		{name: "transient", att: &fakeAttestor{ok: true, err: errors.New("apiserver down")}, code: codes.Unavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer("http://127.0.0.1:1", mapping).WithWorkloadAttestor(tc.att, errDenied)
			key, id, err := s.resolve(context.Background(), creds)
			if tc.code != codes.OK {
				if status.Code(err) != tc.code {
					t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.code)
				}
				return
			}
			if err != nil || key != tc.wantKey || id != tc.wantID {
				t.Fatalf("key=%q id=%q err=%v", key, id, err)
			}
			if tc.att.pid != 4242 {
				t.Fatalf("attestor saw pid %d", tc.att.pid)
			}
		})
	}
}

func TestResolveWithoutAttestorUsesMapping(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", Mapping{7: "spiffe://omega.local/x"})
	if _, _, err := s.resolve(context.Background(), attestor.Creds{UID: 8}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unmapped uid: %v", err)
	}
	key, _, err := s.resolve(context.Background(), attestor.Creds{UID: 7})
	if err != nil || key != "uid:7" {
		t.Fatalf("key=%q err=%v", key, err)
	}
}

func TestFetchJWTSVIDRefusesAnotherWorkloadsID(t *testing.T) {
	att := &fakeAttestor{id: "spiffe://omega.local/k8s/apps/web", ok: true}
	s := NewServer("http://127.0.0.1:1", nil).WithWorkloadAttestor(att, errDenied)
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &attestor.CredAddr{Base: &net.UnixAddr{Name: "@", Net: "unix"}, Creds: attestor.Creds{UID: 0, PID: 99}},
	})
	_, err := s.FetchJWTSVID(ctx, &workloadpb.JWTSVIDRequest{SpiffeId: "spiffe://omega.local/k8s/kube-system/admin", Audience: []string{"x"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, want PermissionDenied", err)
	}
}
