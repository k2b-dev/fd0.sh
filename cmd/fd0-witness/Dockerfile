# fd0-witness multistage build.
#
#   docker build -t fd0-witness -f cmd/fd0-witness/Dockerfile .
#   docker run --rm -p 4049:4049 \
#       -v fd0-witness-data:/data \
#       -e FD0_WITNESS_BIND=:4049 \
#       -e FD0_WITNESS_KEY=/data/witness.key \
#       fd0-witness
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
    -o /out/fd0-witness ./cmd/fd0-witness

# ─── Stage 2: runtime ────────────────────────────────────────────────────
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/fd0-witness /fd0-witness

# Default state under /data so a `-v fd0-witness-data:/data` volume
# persists the SQLite archive AND the cosign key file across upgrades.
ENV FD0_WITNESS_DB=/data/witness.db \
    FD0_WITNESS_BIND=:4049

EXPOSE 4049
VOLUME ["/data"]

ENTRYPOINT ["/fd0-witness"]
