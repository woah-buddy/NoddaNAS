# syntax=docker/dockerfile:1
#
# NoddaNAS container image.
#   - Static Go binary (no libc, no shell, no package manager in the image)
#   - Distroless base, runs as an unprivileged user (UID 65532)
#   - Designed for a read-only root filesystem; only /data is writable
# For production, pin both base images by digest (Dependabot keeps them fresh).

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/noddanas ./cmd/noddanas \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.title="NoddaNAS" \
      org.opencontainers.image.description="Self-hosted, secure-by-design file storage" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/woah-buddy/NoddaNAS"
COPY --from=build /out/noddanas /noddanas
# A named volume mounted here inherits this ownership on first use.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/noddanas", "healthcheck"]
ENTRYPOINT ["/noddanas"]
CMD ["serve"]
