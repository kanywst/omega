.PHONY: demo down

DEMO_DIR := /tmp/omega-oidc-federation-demo

# `make demo` boots an in-process mock OIDC IdP, an omega server
# wired to that IdP via --oidc-idp, signs a representative ID token
# for `alice@example.com`, exchanges it at /v1/oidc/exchange, and
# verifies that the rendered SPIFFE ID and the RFC 8693 `act` claim
# on the issued JWT-SVID both match what the configured template
# and validated upstream claims dictate.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f 'omega server --http-addr 127.0.0.1:18180' 2>/dev/null || true
	@pkill -f '$(DEMO_DIR)/mock-idp' 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
