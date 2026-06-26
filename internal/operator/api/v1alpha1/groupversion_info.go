// Package v1alpha1 contains API Schema definitions for the
// omega.kanywst.github.io v1alpha1 API group.
//
// +kubebuilder:object:generate=true
// +groupName=omega.kanywst.github.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group / version used to register objects.
	GroupVersion = schema.GroupVersion{Group: "omega.kanywst.github.io", Version: "v1alpha1"}

	schemeBuilder = runtime.NewSchemeBuilder()

	// AddToScheme is the function operator main calls to register the
	// CRD types onto a controller-runtime manager's scheme.
	AddToScheme = schemeBuilder.AddToScheme
)

// register adds the supplied types to the scheme builder under
// GroupVersion. Each types file calls this from its init() instead of
// using the deprecated controller-runtime scheme.Builder helper.
func register(objs ...runtime.Object) {
	schemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, objs...)
		metav1.AddToGroupVersion(s, GroupVersion)
		return nil
	})
}
