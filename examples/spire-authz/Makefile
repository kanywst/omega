.PHONY: demo down

# `make demo` runs SPIRE as the identity issuer and Omega as the
# authorization and audit layer on top of it: callers authenticate with
# their SPIRE SVIDs, Cedar decides by SPIRE path and by groups pushed over
# SCIM, a node agent decides locally, and every decision lands in one
# audit chain. Needs Docker; takes a few minutes on a cold image cache.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-docker compose --env-file $(CURDIR)/run/demo.env down -v --remove-orphans 2>/dev/null || true
	@rm -rf $(CURDIR)/run
	@echo "[demo] torn down"
