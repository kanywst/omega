.PHONY: demo down

DEMO_DIR := /tmp/omega-ca-aws-pca-demo

# `make demo` boots a tiny mock AWS Private CA and an omega server
# wired with --ca-backend=aws-pca, then proves the issued X.509-SVID
# is signed by the mock's issuing CA (not by omega's local
# self-signed default).
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-[ -f $(DEMO_DIR)/server.pid ] && kill $$(cat $(DEMO_DIR)/server.pid) 2>/dev/null || true
	@-[ -f $(DEMO_DIR)/pca.pid    ] && kill $$(cat $(DEMO_DIR)/pca.pid)    2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
