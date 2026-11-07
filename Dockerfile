# anvilkit-job-access-sidecar: the trusted access sidecar of a Job Pod
# (DD-03 §5). Built from this repository alone; the generated contract
# module is an ordinary versioned dependency resolved through GOPROXY (the
# declared version in go.mod). The parent's deploy/dev/images.sh uses this
# same standalone build, without a workspace replacement.
FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ARG GOPROXY=https://proxy.golang.org,direct
ARG GONOSUMDB=
ENV GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOPROXY=$GOPROXY GONOSUMDB=$GONOSUMDB
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/anvilkit-job-access-sidecar ./cmd/anvilkit-job-access-sidecar

# Runtime: the binary, the reviewed secret-free configuration and the
# sidecar user (10002). The launch identity (the launch secret among it,
# DEC-045), the Control address and the identity mode come from the Job
# template through the allowlisted ANVILKIT_SIDECAR_* variables; workload
# certificates are mounted by the environment. The sockets are
# abstract-namespace names: no directory is needed. No capability is
# granted and none is needed.
FROM alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a
# Alpine zlib CVE-2026-4738: the base ships 1.3.2-r1 and v3.24/main serves
# the fixed 1.4-r0. A floor, not a pin: the build fails while the index
# lacks it, and drop this step once the alpine:3.24 pin ships >= 1.4-r0.
RUN apk add --no-cache 'zlib>=1.4-r0'
RUN addgroup -g 10002 sidecar && adduser -D -H -u 10002 -G sidecar -s /sbin/nologin sidecar \
 && mkdir -p /etc/anvilkit/anvilkit-job-access-sidecar
COPY --from=build /out/anvilkit-job-access-sidecar /usr/local/bin/anvilkit-job-access-sidecar
COPY --chmod=0644 config.yaml /etc/anvilkit/anvilkit-job-access-sidecar/config.yaml
ENV ANVILKIT_SIDECAR_CONFIG=/etc/anvilkit/anvilkit-job-access-sidecar/config.yaml
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/anvilkit-job-access-sidecar"]
