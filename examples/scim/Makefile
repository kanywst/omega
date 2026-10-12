.PHONY: demo down

DEMO_DIR := /tmp/omega-scim-demo

# `make demo` plays an identity provider pushing users and groups to
# Omega over SCIM 2.0, and shows the Cedar decision following each
# provisioning change: a group grant, a new member, a deactivation.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@pkill -f '$(DEMO_DIR)/' 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
