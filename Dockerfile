# build
FROM golang:1.22-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app
COPY . .
RUN go build -o main ./cmd/main.go

# runner
FROM alpine:latest
RUN apk update && apk --no-cache add ca-certificates
WORKDIR /app/
COPY --from=builder /app/main .

CMD ["./main"]
