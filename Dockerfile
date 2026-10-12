# syntax=docker/dockerfile:1.7

# The builder runs on the build machine's own platform and cross-compiles
# (CGO is off), so an arm64 image needs no emulation: the target stage only
# copies the binary.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w -X github.com/kanywst/omega/internal/version.Version=${VERSION}" \
      -o /out/omega ./cmd/omega

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/omega /usr/local/bin/omega
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/omega"]
CMD ["--help"]
