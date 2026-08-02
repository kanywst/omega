.PHONY: demo down

DEMO_DIR := /tmp/omega-spire-upstream-demo

# `make demo` runs omega with --identity-source=spire-upstream against a
# stand-in upstream trust domain, asserts issuance stays disabled (501),
# then rotates the upstream CA and signing key and SIGHUPs. Covers the
# fail-closed path (a corrupt bundle keeps the previous anchors) and the
# spiffe_sequence envelope field peers use to detect the rotation.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-[ -f $(DEMO_DIR)/server.pid ] && kill $$(cat $(DEMO_DIR)/server.pid) 2>/dev/null || true
	@-[ -f $(DEMO_DIR)/upstream.pid ] && kill $$(cat $(DEMO_DIR)/upstream.pid) 2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
