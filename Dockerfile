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

# Store boot file defaults in a non-volume path so they survive volume mounts.
# The application copies missing files from here to /tftpboot on startup.
COPY undionly-custom.kpxe /opt/pxemanager/defaults/undionly.kpxe
COPY boot.ipxe /opt/pxemanager/defaults/boot.ipxe
COPY memdisk /opt/pxemanager/defaults/memdisk
COPY vmlinuz /opt/pxemanager/defaults/vmlinuz
COPY initramfs /opt/pxemanager/defaults/initramfs

EXPOSE 69/udp
EXPOSE 8080/tcp

CMD in.tftpd -L -s /tftpboot & exec pxemanager
