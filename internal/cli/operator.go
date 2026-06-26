package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmissuerv1alpha1 "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuercontrollers "github.com/cert-manager/issuer-lib/controllers"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	omegav1alpha1 "github.com/kanywst/omega/internal/operator/api/v1alpha1"
	"github.com/kanywst/omega/internal/operator/controller"
)

// scheme aggregates the K8s built-in types (Pods, Events, ...) and the
// Omega CRD group. The manager needs both: built-ins for the
// leader-election ConfigMap/Lease and event recorder, Omega CRDs for
// the Get/Update calls in the reconciler.
var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(omegav1alpha1.AddToScheme(scheme))
	// cert-manager CertificateRequest is the resource issuer-lib's
	// CombinedController watches; the cluster doesn't have to advertise
	// the type to register it locally - we only need to encode/decode
	// the wire format.
	utilruntime.Must(cmapi.AddToScheme(scheme))
}

func newOperatorCommand() *cobra.Command {
	var (
		metricsAddr string
		probeAddr   string
		leaderElect bool
		omegaURL    string
		electionID  string
	)

	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Run the Omega Kubernetes operator (CRD reconciler)",
		Long: `Run the Omega operator: a controller-runtime manager that watches
OmegaDomain CRs and ensures the corresponding domain exists on the
Omega control plane addressed by --omega-url.

Out-of-cluster runs use the default kubeconfig (KUBECONFIG env or
~/.kube/config). In-cluster runs use the pod's service-account token.`,
		RunE: func(c *cobra.Command, _ []string) error {
			ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
				Scheme:                 scheme,
				Metrics:                metricsserver.Options{BindAddress: metricsAddr},
				HealthProbeBindAddress: probeAddr,
				LeaderElection:         leaderElect,
				LeaderElectionID:       electionID,
			})
			if err != nil {
				return fmt.Errorf("manager: %w", err)
			}

			if err := (&controller.DomainReconciler{
				Client:   mgr.GetClient(),
				OmegaURL: omegaURL,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("setup OmegaDomain controller: %w", err)
			}

			ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// issuer-lib's CombinedController wants events.EventRecorder
			// (the v1 events API) rather than the legacy
			// record.EventRecorder that mgr.GetEventRecorderFor returns,
			// so we build our own broadcaster against the in-cluster
			// kubernetes clientset.
			clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
			if err != nil {
				return fmt.Errorf("kubernetes clientset: %w", err)
			}
			eventBroadcaster := events.NewEventBroadcasterAdapterWithContext(ctx, clientset)
			eventBroadcaster.StartRecordingToSink(ctx.Done())

			sgnr := &controller.IssuerSigner{}
			if err := (&issuercontrollers.CombinedController{
				IssuerTypes:        []cmissuerv1alpha1.Issuer{&omegav1alpha1.OmegaIssuer{}},
				ClusterIssuerTypes: []cmissuerv1alpha1.Issuer{&omegav1alpha1.OmegaClusterIssuer{}},
				FieldOwner:         "omega-operator.kanywst.github.io",
				EventRecorder:      eventBroadcaster.NewRecorder("omega-operator"),
				Sign:               sgnr.Sign,
				Check:              sgnr.Check,
			}).SetupWithManager(ctx, mgr); err != nil {
				return fmt.Errorf("setup OmegaIssuer controllers: %w", err)
			}

			if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
				return fmt.Errorf("add healthz: %w", err)
			}
			if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
				return fmt.Errorf("add readyz: %w", err)
			}

			fmt.Fprintf(os.Stderr, "omega operator: omega-url=%s leader-elect=%v metrics=%s probes=%s\n",
				omegaURL, leaderElect, metricsAddr, probeAddr)
			return mgr.Start(ctx)
		},
	}

	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":8081", "address the metrics endpoint binds to")
	cmd.Flags().StringVar(&probeAddr, "health-addr", ":8082", "address the health/readiness endpoints bind to")
	cmd.Flags().BoolVar(&leaderElect, "leader-elect", false, "enable leader election for HA operator deployments")
	cmd.Flags().StringVar(&electionID, "leader-election-id", "omega-operator.kanywst.github.io", "lease name used for leader election")
	cmd.Flags().StringVar(&omegaURL, "omega-url", "http://omega-server:8080", "Omega control plane base URL the reconciler talks to")

	return cmd
}
