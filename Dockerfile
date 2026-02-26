FROM alpine:3.21
RUN apk add --no-cache tftp-hpa
COPY pxemanager /usr/local/bin/pxemanager

# Store boot file defaults in a non-volume path so they survive volume mounts.
# The application copies missing files from here to /tftpboot on startup.
COPY undionly-custom.kpxe /opt/pxemanager/defaults/undionly.kpxe
COPY ipxe.efi /opt/pxemanager/defaults/ipxe.efi
COPY boot.ipxe /opt/pxemanager/defaults/boot.ipxe
COPY memdisk /opt/pxemanager/defaults/memdisk
COPY fedora-ks.cfg /opt/pxemanager/defaults/fedora-ks.cfg
COPY fedora-builder-ks.cfg /opt/pxemanager/defaults/fedora-builder-ks.cfg
COPY builder.ign /opt/pxemanager/defaults/builder.ign
COPY live-builder.ign /opt/pxemanager/defaults/live-builder.ign

EXPOSE 69/udp
EXPOSE 80/tcp

CMD in.tftpd -L -s /tftpboot & exec pxemanager
