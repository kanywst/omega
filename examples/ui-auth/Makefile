.PHONY: demo down

DEMO_DIR := /tmp/omega-ui-auth-demo

# `make demo` signs a person in to the web UI through a mock OIDC IdP,
# then creates, updates and deletes a Cedar policy through the UI's API
# routes, and checks the audit chain names the person as actor and the
# UI as via. Needs Go, Node.js 20+, openssl and python3.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-for p in server mock-idp ui; do [ -f $(DEMO_DIR)/$$p.pid ] && kill $$(cat $(DEMO_DIR)/$$p.pid) 2>/dev/null; done; true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
