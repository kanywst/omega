.PHONY: demo down

DEMO_DIR := /tmp/omega-ca-rotation-demo

# `make demo` rotates the built-in CA of a running control plane with
# `omega ca prepare|activate|retire` and SIGHUP, and checks the bundle,
# the JWKS, spiffe_sequence and which tokens verify at every step.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f '$(DEMO_DIR)/' 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
