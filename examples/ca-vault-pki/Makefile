.PHONY: demo down

DEMO_DIR := /tmp/omega-ca-vault-pki-demo

# `make demo` boots a tiny mock Vault PKI engine and an omega
# server wired with --ca-backend=vault-pki, then proves the issued
# X.509-SVID is signed by the mock Vault CA (not by omega's local
# self-signed default).
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-[ -f $(DEMO_DIR)/server.pid ] && kill $$(cat $(DEMO_DIR)/server.pid) 2>/dev/null || true
	@-[ -f $(DEMO_DIR)/vault.pid  ] && kill $$(cat $(DEMO_DIR)/vault.pid)  2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
