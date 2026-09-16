# anvilkit-job-access-sidecar: the trusted access sidecar of a Job Pod
# (DD-03 §5). Built from this repository alone; the generated contract
# module is an ordinary versioned dependency resolved through GOPROXY (the
# pseudo-version of the pushed contracts commit that carries
# ExecutionService.GetInstance and its operation view, until a tag exists).
# The parent checkout's deploy/dev/images.sh builds the development image
# against its contracts checkout instead (DEVELOPMENT_ONLY).
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
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
# sidecar user (10002). The launch identity, the Control address and the
# identity mode come from the Job template through the allowlisted
# ANVILKIT_SIDECAR_* variables; workload certificates are mounted by the
# environment. No capability is granted and none is needed.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN addgroup -g 10002 sidecar && adduser -D -H -u 10002 -G sidecar -s /sbin/nologin sidecar \
 && mkdir -p /etc/anvilkit/anvilkit-job-access-sidecar /run/anvilkit
COPY --from=build /out/anvilkit-job-access-sidecar /usr/local/bin/anvilkit-job-access-sidecar
COPY --chmod=0644 config.yaml /etc/anvilkit/anvilkit-job-access-sidecar/config.yaml
ENV ANVILKIT_SIDECAR_CONFIG=/etc/anvilkit/anvilkit-job-access-sidecar/config.yaml
USER 10002:10002
ENTRYPOINT ["/usr/local/bin/anvilkit-job-access-sidecar"]
