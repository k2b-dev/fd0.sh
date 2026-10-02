# fd0-server multistage build.
#
#   docker build -t fd0-server .
#   docker run --rm -p 4048:4048 -v fd0-data:/data fd0-server
#
# Final image: scratch + statically-linked Go binary + CA bundle. ~18 MB.

# ─── Stage 1: build ──────────────────────────────────────────────────────
FROM golang:1.26-alpine AS build

RUN apk add --no-cache ca-certificates git
WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -tags=netgo \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/fd0-server ./cmd/fd0-server

# ─── Stage 2: runtime ────────────────────────────────────────────────────
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/fd0-server /fd0-server

# Default FD0_DB lives under /data so a `-v fd0-data:/data` volume persists
# state. Override with FD0_DB env or --db flag.
ENV FD0_BIND=:4048 \
    FD0_DB=/data/fd0.db

EXPOSE 4048
VOLUME ["/data"]

ENTRYPOINT ["/fd0-server"]
