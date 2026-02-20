FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o pxemanager .

FROM alpine:latest
RUN apk add --no-cache tftp-hpa
COPY --from=builder /build/pxemanager /usr/local/bin/pxemanager
COPY undionly-custom.kpxe /tftpboot/undionly.kpxe
COPY boot.ipxe /tftpboot/boot.ipxe
COPY memdisk /tftpboot/memdisk

EXPOSE 69/udp
EXPOSE 8080/tcp

CMD in.tftpd -L -s /tftpboot & exec pxemanager
