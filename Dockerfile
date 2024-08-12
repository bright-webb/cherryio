FROM golang:1.22 AS builder

WORKDIR /app

# Copy the Go Modules manifests
COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o main .

FROM debian:bullseye-slim

WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 6001

CMD ["./main"]
