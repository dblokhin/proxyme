# build
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o proxyme

# runner
FROM scratch
WORKDIR /app/
COPY --from=builder /app/proxyme .

CMD ["./main"]
