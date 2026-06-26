package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	cmissuerv1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
)

// OmegaIssuerSpec configures the connection to the Omega control plane
// used to sign cert-manager CertificateRequests routed to this issuer.
//
// SPIFFE ID resolution: the SPIFFE ID for the issued SVID is taken
// from the *first URI SAN* of the CSR. Workloads must therefore set
// `spec.uris: ["spiffe://<trust-domain>/<path>"]` on their
// cert-manager Certificate. This matches the way cert-manager-csi-driver-spiffe
// formulates SPIFFE-bound CSRs and means Omega never has to second-guess
// which identity to issue.
type OmegaIssuerSpec struct {
	// URL is the base URL of the Omega control plane (e.g.
	// http://omega-server.omega-system.svc:8080). The reconciler talks
	// HTTP to {URL}/v1/svid and {URL}/v1/bundle.
	URL string `json:"url"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=oissuer

// OmegaIssuer is a namespaced cert-manager external issuer backed by an
// Omega control plane. CertificateRequests in the same namespace that
// reference this issuer are signed via Omega's /v1/svid endpoint.
type OmegaIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OmegaIssuerSpec               `json:"spec,omitempty"`
	Status            cmissuerv1alpha1.IssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OmegaIssuerList is the kubectl response shape for `kubectl get omegaissuer`.
type OmegaIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OmegaIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ocissuer

// OmegaClusterIssuer is the cluster-scoped variant. CertificateRequests
// in *any* namespace that reference this issuer (kind=OmegaClusterIssuer)
// are signed via Omega's /v1/svid endpoint.
type OmegaClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OmegaIssuerSpec               `json:"spec,omitempty"`
	Status            cmissuerv1alpha1.IssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OmegaClusterIssuerList is the response shape for `kubectl get omegaclusterissuer`.
type OmegaClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OmegaClusterIssuer `json:"items"`
}

func init() {
	register(
		&OmegaIssuer{}, &OmegaIssuerList{},
		&OmegaClusterIssuer{}, &OmegaClusterIssuerList{},
	)
}

// Issuer interface methods (issuer-lib v1alpha1.Issuer). Both Issuer
// and ClusterIssuer expose conditions through Status.Conditions and
// share the same type identifier prefix; the Kind segment differs and
// is encoded by the resource plural.

// GetConditions exposes the Ready condition slice to issuer-lib.
func (i *OmegaIssuer) GetConditions() []metav1.Condition { return i.Status.Conditions }

// GetIssuerTypeIdentifier returns the "<plural>.<group>" identifier
// used by issuer-lib to discover which CertificateRequests this signer
// owns and how to encode CSR issuerName values.
func (i *OmegaIssuer) GetIssuerTypeIdentifier() string {
	return "omegaissuers.omega.kanywst.github.io"
}

// GetConditions exposes the Ready condition slice to issuer-lib.
func (i *OmegaClusterIssuer) GetConditions() []metav1.Condition { return i.Status.Conditions }

// GetIssuerTypeIdentifier returns the "<plural>.<group>" identifier
// used by issuer-lib to discover which CertificateRequests this signer
// owns and how to encode CSR issuerName values.
func (i *OmegaClusterIssuer) GetIssuerTypeIdentifier() string {
	return "omegaclusterissuers.omega.kanywst.github.io"
}

// DeepCopy / DeepCopyInto / DeepCopyObject. Hand-written for the same
// reason as OmegaDomain - keeps the build free of code generation.

func (in *OmegaIssuer) DeepCopyInto(out *OmegaIssuer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

func (in *OmegaIssuer) DeepCopy() *OmegaIssuer {
	if in == nil {
		return nil
	}
	out := new(OmegaIssuer)
	in.DeepCopyInto(out)
	return out
}

func (in *OmegaIssuer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *OmegaIssuerList) DeepCopyInto(out *OmegaIssuerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]OmegaIssuer, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *OmegaIssuerList) DeepCopy() *OmegaIssuerList {
	if in == nil {
		return nil
	}
	out := new(OmegaIssuerList)
	in.DeepCopyInto(out)
	return out
}

func (in *OmegaIssuerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *OmegaClusterIssuer) DeepCopyInto(out *OmegaClusterIssuer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

func (in *OmegaClusterIssuer) DeepCopy() *OmegaClusterIssuer {
	if in == nil {
		return nil
	}
	out := new(OmegaClusterIssuer)
	in.DeepCopyInto(out)
	return out
}

func (in *OmegaClusterIssuer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *OmegaClusterIssuerList) DeepCopyInto(out *OmegaClusterIssuerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]OmegaClusterIssuer, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *OmegaClusterIssuerList) DeepCopy() *OmegaClusterIssuerList {
	if in == nil {
		return nil
	}
	out := new(OmegaClusterIssuerList)
	in.DeepCopyInto(out)
	return out
}

func (in *OmegaClusterIssuerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
