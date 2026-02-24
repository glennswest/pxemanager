FROM alpine:3.21
RUN apk add --no-cache tftp-hpa
COPY pxemanager /usr/local/bin/pxemanager

# Store boot file defaults in a non-volume path so they survive volume mounts.
# The application copies missing files from here to /tftpboot on startup.
COPY undionly-custom.kpxe /opt/pxemanager/defaults/undionly.kpxe
COPY ipxe.efi /opt/pxemanager/defaults/ipxe.efi
COPY boot.ipxe /opt/pxemanager/defaults/boot.ipxe
COPY memdisk /opt/pxemanager/defaults/memdisk
COPY vmlinuz /opt/pxemanager/defaults/vmlinuz
COPY initramfs /opt/pxemanager/defaults/initramfs

EXPOSE 69/udp
EXPOSE 80/tcp

CMD in.tftpd -L -s /tftpboot & exec pxemanager
