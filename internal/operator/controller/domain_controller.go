// Package controller hosts the reconcilers that translate Omega CRDs
// into HTTP calls against the Omega control plane.
package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kanywst/omega/internal/server/storage"

	omegav1alpha1 "github.com/kanywst/omega/internal/operator/api/v1alpha1"
)

// DomainReconciler watches OmegaDomain CRs and ensures the corresponding
// domain exists on an Omega control plane addressed by OmegaURL.
type DomainReconciler struct {
	client.Client
	OmegaURL   string
	HTTPClient *http.Client
}

// SetupWithManager registers the reconciler with the controller-runtime
// manager. Cluster-scoped (no namespace filter).
func (r *DomainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.HTTPClient == nil {
		r.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&omegav1alpha1.OmegaDomain{}).
		Named("omegadomain").
		Complete(r)
}

// createRetryInterval is how soon a failed create is retried.
const createRetryInterval = 5 * time.Second

// Reconcile makes the Omega control plane match the desired state of
// the CR. The control plane already enforces uniqueness on domain.name,
// so the loop is "GET to check existence; POST if missing; record
// outcome in status". spec.admins is applied only when the domain is
// created; later edits are not reconciled.
func (r *DomainReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var domain omegav1alpha1.OmegaDomain
	if err := r.Get(ctx, req.NamespacedName, &domain); err != nil {
		if apierrors.IsNotFound(err) {
			// CR deleted; we intentionally do not delete the domain on
			// the control plane - destruction is an explicit operator
			// action via `omega domain delete`, not something a kubectl
			// delete should do silently.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	name := domain.Spec.DomainName
	if name == "" {
		name = domain.Name
	}

	exists, err := r.domainExists(ctx, name)
	if err != nil {
		return ctrl.Result{}, r.markCondition(ctx, &domain, metav1.ConditionFalse, "OmegaUnreachable", err.Error())
	}
	if !exists {
		if err := r.createDomain(ctx, name, domain.Spec.Description, domain.Spec.Admins); err != nil {
			var rej *rejectedError
			if errors.As(err, &rej) {
				// The spec itself is wrong (invalid name or admin, or the
				// operator lacks authority): retrying cannot help until
				// the object changes, which triggers a new reconcile.
				_ = r.markCondition(ctx, &domain, metav1.ConditionFalse, "CreateRejected", err.Error())
				return ctrl.Result{}, nil
			}
			// Retry: the usual cause is a parent OmegaDomain that has not
			// been reconciled yet.
			return ctrl.Result{RequeueAfter: createRetryInterval}, r.markCondition(ctx, &domain, metav1.ConditionFalse, "CreateFailed", err.Error())
		}
		logger.Info("created omega domain", "name", name)
	}

	return ctrl.Result{}, r.markCondition(ctx, &domain, metav1.ConditionTrue, "Ready", "domain present on control plane")
}

func (r *DomainReconciler) domainExists(ctx context.Context, name string) (bool, error) {
	url := strings.TrimRight(r.OmegaURL, "/") + "/v1/domains/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("GET %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

func (r *DomainReconciler) createDomain(ctx context.Context, name, description string, admins []string) error {
	body, err := json.Marshal(map[string]any{"name": name, "description": description, "admins": admins})
	if err != nil {
		return err
	}
	url := strings.TrimRight(r.OmegaURL, "/") + "/v1/domains"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusConflict {
		// Race with another reconcile or a manual `omega domain create`.
		// Idempotent path - treat as success.
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	err = fmt.Errorf("POST %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	// A 400 for a missing parent is transient; every other 4xx except
	// 429 rejects the spec or the operator's authority.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests &&
		!strings.Contains(string(raw), storage.ErrParentNotFound.Error()) {
		return &rejectedError{err}
	}
	return err
}

// rejectedError is a create the control plane refused for a reason a
// retry cannot fix.
type rejectedError struct{ error }

func (e *rejectedError) Unwrap() error { return e.error }

func (r *DomainReconciler) markCondition(ctx context.Context, d *omegav1alpha1.OmegaDomain, status metav1.ConditionStatus, reason, message string) error {
	cond := metav1.Condition{
		Type:               "Ready",
		Status:             status,
		ObservedGeneration: d.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
	d.Status.ObservedGeneration = d.Generation
	d.Status.Conditions = upsertCondition(d.Status.Conditions, cond)
	if err := r.Status().Update(ctx, d); err != nil && !apierrors.IsConflict(err) {
		return err
	}
	if status == metav1.ConditionFalse {
		return errors.New(message)
	}
	return nil
}

func upsertCondition(conds []metav1.Condition, c metav1.Condition) []metav1.Condition {
	for i := range conds {
		if conds[i].Type == c.Type {
			if conds[i].Status == c.Status {
				c.LastTransitionTime = conds[i].LastTransitionTime
			}
			conds[i] = c
			return conds
		}
	}
	return append(conds, c)
}
