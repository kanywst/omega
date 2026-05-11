.PHONY: demo down

DEMO_DIR := /tmp/omega-audit-otlp-demo

# `make demo` boots a small OTLP/HTTP-protobuf logs receiver and an
# omega server wired to forward audit events to it. The script
# drives a domain create + an AuthZEN evaluation, then asserts the
# sink received both audit rows and that every emitted LogRecord
# carries the hash-chain fields as OTLP attributes.
demo:
	@bash $(CURDIR)/run-demo.sh

down:
	@-[ -f $(DEMO_DIR)/server.pid ] && kill $$(cat $(DEMO_DIR)/server.pid) 2>/dev/null || true
	@-[ -f $(DEMO_DIR)/sink.pid   ] && kill $$(cat $(DEMO_DIR)/sink.pid)   2>/dev/null || true
	@rm -rf $(DEMO_DIR)
	@echo "[demo] torn down"
