.PHONY: demo down

DEMO_DIR := /tmp/omega-id-jag-demo

# `make demo` runs a stand-in enterprise IdP, an omega control plane
# trusting it for ID-JAGs, and the MCP tool-server, then drives the
# agent through IdP -> ID-JAG -> omega -> tool and two negative cases.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f '$(DEMO_DIR)/' 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
