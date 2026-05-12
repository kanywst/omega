.PHONY: demo down

DEMO_DIR := /tmp/omega-k8s-attest-demo

# `make demo` boots a kind cluster, starts omega server out-of-cluster
# with `--k8s-attest`, mints a ServiceAccount token, exchanges it at
# `POST /v1/attest/k8s` for an X.509-SVID, and verifies that:
#   - the rendered SPIFFE ID matches the template, and
#   - the same flow with a wrong audience returns 401 (TokenReview
#     rejection becomes an audited deny on the omega side).
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-[ -f $(DEMO_DIR)/server.pid ] && kill $$(cat $(DEMO_DIR)/server.pid) 2>/dev/null || true
	@-kind delete cluster --name omega-k8s-attest >/dev/null 2>&1 || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
