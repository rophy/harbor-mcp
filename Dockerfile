FROM golang:1.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /harbor-mcp ./cmd/harbor-mcp/

FROM gcr.io/distroless/static-debian12
COPY --from=builder /harbor-mcp /harbor-mcp
VOLUME /data
ENTRYPOINT ["/harbor-mcp"]
