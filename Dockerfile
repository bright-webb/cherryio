FROM golang:alpine AS builder

# Install necessary packages and Supervisord
RUN apk add --no-cache supervisor coreutils && rm -rf /var/cache/apk/*

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o main .

RUN mkdir -p /etc/supervisor/conf.d
COPY supervisord.conf /etc/supervisor/conf.d/

FROM debian:bullseye-slim


RUN apt-get update && apt-get install -y supervisor && apt-get clean

WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /etc/supervisor/conf.d /etc/supervisor/conf.d

EXPOSE 6001

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
