# syntax=docker/dockerfile:1.7
#
# Sidecar image for examples/envoy-ext-authz. Builds the AuthZEN bridge
# that Envoy's ext_authz HTTP filter calls into.

FROM golang:1.26.6-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags '-s -w' \
      -o /out/authzen-adapter ./examples/envoy-ext-authz/authzen-adapter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/authzen-adapter /usr/local/bin/authzen-adapter
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/authzen-adapter"]
