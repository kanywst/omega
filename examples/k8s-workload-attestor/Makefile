.PHONY: demo down

# `make demo` boots a kind cluster, runs omega server and omega agent
# --k8s-workload-attestor inside its node, and checks that a pod gets its
# pod's SPIFFE ID while a host process with the same UID gets the UID
# mapping.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-kind delete cluster --name omega-k8s-wl >/dev/null 2>&1 || true
	@rm -rf /tmp/omega-k8s-workload-attestor-demo
	@echo "[demo] torn down"
