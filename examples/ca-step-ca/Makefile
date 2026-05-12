.PHONY: demo down

DEMO_DIR := /tmp/omega-ca-step-ca-demo

# `make demo` boots an in-process mock step-ca and an omega server
# wired to it via --ca-backend=step-ca, signs a workload CSR through
# POST /v1/svid, and asserts the issued leaf both chains to the mock
# step-ca root and carries the requested SPIFFE ID URI SAN. The mock
# verifies omega's OTT signature, so a regression that breaks OTT
# generation trips the demo.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-[ -f $(DEMO_DIR)/server.pid    ] && kill $$(cat $(DEMO_DIR)/server.pid)    2>/dev/null || true
	@-[ -f $(DEMO_DIR)/step-ca.pid   ] && kill $$(cat $(DEMO_DIR)/step-ca.pid)   2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
