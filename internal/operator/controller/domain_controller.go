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

// Reconcile makes the Omega control plane match the desired state of
// the CR. The control plane already enforces uniqueness on domain.name,
// so the loop is "GET to check existence; POST if missing; record
// outcome in status".
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
		if err := r.createDomain(ctx, name, domain.Spec.Description); err != nil {
			return ctrl.Result{}, r.markCondition(ctx, &domain, metav1.ConditionFalse, "CreateFailed", err.Error())
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

func (r *DomainReconciler) createDomain(ctx context.Context, name, description string) error {
	body, err := json.Marshal(map[string]string{"name": name, "description": description})
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
	return fmt.Errorf("POST %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
}

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
