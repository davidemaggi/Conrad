# syntax=docker/dockerfile:1
# Conrad: static binary on distroless. Build from the repository root:
#   docker build -f deploy/Dockerfile -t conrad .

FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN mkdir -p ../internal/web/dist && npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/web/dist ./internal/web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/conrad ./cmd/conrad
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/conrad /usr/local/bin/conrad
COPY --from=build --chown=65532:65532 /out/data /data
ENV CONRAD_DATA_DIR=/data
VOLUME /data
EXPOSE 80 443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/usr/local/bin/conrad", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/conrad"]
CMD ["serve"]
