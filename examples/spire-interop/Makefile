.PHONY: demo down

# `make demo` runs omega against upstream spire-server and spire-agent
# images: real join-token node attestation, a real registration entry, and
# SPIRE's own localauthority command rotating the X.509 CA and the JWT
# signing key. It asserts omega serves SPIRE's anchors, refuses to issue, and
# follows both rotations with nothing signalling it. Needs Docker; takes
# about three minutes on a cold image cache. See ADR 0010.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-docker compose --env-file $(CURDIR)/run/demo.env down -v --remove-orphans 2>/dev/null || true
	@rm -rf $(CURDIR)/run
	@echo "[demo] torn down"
