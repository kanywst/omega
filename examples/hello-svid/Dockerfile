# syntax=docker/dockerfile:1.7
#
# Demo image for examples/hello-svid. Builds both server and client into
# a single distroless image; compose / k8s pick the entrypoint per service.

FROM golang:1.26.6-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags '-s -w' \
      -o /out/hello-svid-server ./examples/hello-svid/server \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags '-s -w' \
      -o /out/hello-svid-client ./examples/hello-svid/client

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/hello-svid-server /usr/local/bin/hello-svid-server
COPY --from=builder /out/hello-svid-client /usr/local/bin/hello-svid-client
USER 65532:65532
