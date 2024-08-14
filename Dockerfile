# build
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o proxyme ./cmd/main.go

# runner
FROM scratch
WORKDIR /
COPY --from=builder /app/proxyme .

ENTRYPOINT ["./proxyme"]
