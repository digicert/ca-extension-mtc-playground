# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mtc-bridge ./cmd/mtc-bridge/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mtc-conformance ./cmd/mtc-conformance/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mtc-assertion ./cmd/mtc-assertion/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mtc-tls-server ./cmd/mtc-tls-server/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mtc-tls-verify ./cmd/mtc-tls-verify/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mtc-verify-cert ./cmd/mtc-verify-cert/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /demo-embedded-cert ./cmd/demo-embedded-cert/

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /mtc-bridge /usr/local/bin/mtc-bridge
COPY --from=builder /mtc-conformance /usr/local/bin/mtc-conformance
COPY --from=builder /mtc-assertion /usr/local/bin/mtc-assertion
COPY --from=builder /mtc-tls-server /usr/local/bin/mtc-tls-server
COPY --from=builder /mtc-tls-verify /usr/local/bin/mtc-tls-verify
COPY --from=builder /mtc-verify-cert /usr/local/bin/mtc-verify-cert
COPY --from=builder /demo-embedded-cert /usr/local/bin/demo-embedded-cert

# Default config location
COPY config.example.yaml /etc/mtc-bridge/config.yaml

EXPOSE 8080 8443 4443

ENTRYPOINT ["mtc-bridge"]
CMD ["-config", "/etc/mtc-bridge/config.yaml"]
