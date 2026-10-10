.PHONY: demo down

DEMO_DIR := /tmp/omega-local-pdp-demo

# `make demo` runs a control plane and a node agent whose local PDP
# decides from the synced policy bundle, then shows a policy change
# reaching the node, decisions landing in the central audit chain, and
# the local PDP failing closed once the control plane is gone.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f '$(DEMO_DIR)/' 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
