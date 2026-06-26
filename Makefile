.PHONY: all build cross test lint tidy clean demo docker-up docker-down docker-demo docker-demo-down install run-server run-agent observability-up observability-down

BIN        := bin/omega
DIST       := dist
PKG        := ./...
GOFLAGS    := -trimpath
LDFLAGS    := -s -w -X github.com/kanywst/omega/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

all: build

build:
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/omega

# Cross-compile for the platforms the quickstart promises.
cross:
	@mkdir -p $(DIST)
	GOOS=linux  GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/omega-linux-amd64  ./cmd/omega
	GOOS=linux  GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/omega-linux-arm64  ./cmd/omega
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/omega-darwin-amd64 ./cmd/omega
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/omega-darwin-arm64 ./cmd/omega

install:
	go install $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/omega

test:
	go test -race -count=1 $(PKG)

lint:
	golangci-lint run

tidy:
	go mod tidy

clean:
	rm -rf bin dist .omega *.db *.db-journal

run-server: build
	$(BIN) server --data-dir .omega

run-agent: build
	$(BIN) agent --socket /tmp/omega-agent.sock

# Bring up control plane + agent + demo client in tmux-style background.
demo: build
	@./scripts/demo.sh

# Bring up the full stack (control plane + agents + hello-svid demo + UI) and
# leave it running. Open http://127.0.0.1:3000 for the dashboard, :8080 for
# the API, :9443 for the demo HTTPS service.
docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v

# One-shot demo path: same stack, but exits once the hello-svid client
# completes its mTLS handshake. Useful for CI smoke tests.
docker-demo:
	docker compose up --build --abort-on-container-exit --exit-code-from hello-svid-client

docker-demo-down:
	docker compose down -v

# Self-contained metrics demo: omega-server + Prometheus + Grafana with the
# "Omega control plane" dashboard auto-provisioned. Uses non-default host
# ports so it can run alongside `make docker-up`.
#
#   Grafana:    http://localhost:13001  (anonymous Admin)
#   Prometheus: http://localhost:19090
#   /metrics:   http://localhost:18080/metrics
observability-up:
	docker compose -f examples/observability/compose.yaml up --build -d

observability-down:
	docker compose -f examples/observability/compose.yaml down -v
