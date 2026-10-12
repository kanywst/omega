.PHONY: demo down

# `make demo` installs the Omega chart into a kind cluster with the SPIFFE
# CSI driver enabled and checks that a pod mounting `csi.spiffe.io` (no
# hostPath) fetches its X.509-SVID from the Omega agent. Needs Docker,
# kind, kubectl and helm.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@kind delete cluster --name omega-csi 2>/dev/null || true
	@echo "[demo] torn down"
