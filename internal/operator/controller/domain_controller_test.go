package controller

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateDomainClassifiesRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     int
		body     string
		wantErr  bool
		rejected bool
	}{
		{"created", http.StatusCreated, "", false, false},
		{"already there", http.StatusConflict, "", false, false},
		{"parent missing is retried", http.StatusBadRequest, `{"error":"parent domain does not exist: \"media\""}`, true, false},
		{"invalid spec is not retried", http.StatusBadRequest, `{"error":"domain label \"Media\" must be lowercase"}`, true, true},
		{"no authority is not retried", http.StatusForbidden, `{"error":"forbidden"}`, true, true},
		{"rate limited is retried", http.StatusTooManyRequests, "", true, false},
		{"server error is retried", http.StatusInternalServerError, "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			r := &DomainReconciler{OmegaURL: srv.URL, HTTPClient: srv.Client()}
			err := r.createDomain(t.Context(), "media.news", "", nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			var rej *rejectedError
			if errors.As(err, &rej) != tc.rejected {
				t.Errorf("rejected = %v, want %v (%v)", !tc.rejected, tc.rejected, err)
			}
		})
	}
}
