# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cve-service ./cmd/cve-service

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/cve-service /cve-service
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/cve-service"]