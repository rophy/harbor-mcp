FROM golang:1.23 AS builder
ARG COVER=false
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN if [ "$COVER" = "true" ]; then \
      CGO_ENABLED=0 go build -cover -o /harbor-mcp ./cmd/harbor-mcp/; \
    else \
      CGO_ENABLED=0 go build -o /harbor-mcp ./cmd/harbor-mcp/; \
    fi

FROM gcr.io/distroless/static-debian12
COPY --from=builder /harbor-mcp /harbor-mcp
VOLUME /data
ENTRYPOINT ["/harbor-mcp"]
CMD ["serve"]
