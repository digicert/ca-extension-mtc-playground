# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mtc-bridge ./cmd/mtc-bridge/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mtc-conformance ./cmd/mtc-conformance/

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /mtc-bridge /usr/local/bin/mtc-bridge
COPY --from=builder /mtc-conformance /usr/local/bin/mtc-conformance

# Default config location
COPY config.example.yaml /etc/mtc-bridge/config.yaml

EXPOSE 8080

ENTRYPOINT ["mtc-bridge"]
CMD ["-config", "/etc/mtc-bridge/config.yaml"]
