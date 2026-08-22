.PHONY: demo down

DEMO_DIR := /tmp/omega-spire-upstream-live-demo

# `make demo` points `omega server --identity-source-workload-api` at a
# mock SPIFFE Workload API socket, rotates the upstream underneath it
# without signalling omega, and asserts /v1/bundle, /v1/jwt/bundle and
# spiffe_sequence follow anyway. See ADR 0010.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-[ -f $(DEMO_DIR)/server.pid   ] && kill $$(cat $(DEMO_DIR)/server.pid)   2>/dev/null || true
	@-[ -f $(DEMO_DIR)/agent.pid    ] && kill $$(cat $(DEMO_DIR)/agent.pid)    2>/dev/null || true
	@-[ -f $(DEMO_DIR)/upstream.pid ] && kill $$(cat $(DEMO_DIR)/upstream.pid) 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
