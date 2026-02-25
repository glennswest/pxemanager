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
COPY fedora-vmlinuz /opt/pxemanager/defaults/fedora-vmlinuz
COPY fedora-initrd.img /opt/pxemanager/defaults/fedora-initrd.img
COPY fedora-ks.cfg /opt/pxemanager/defaults/fedora-ks.cfg
COPY fedora-builder-ks.cfg /opt/pxemanager/defaults/fedora-builder-ks.cfg
COPY coreos-kernel /opt/pxemanager/defaults/coreos-kernel
COPY coreos-initramfs /opt/pxemanager/defaults/coreos-initramfs
COPY coreos-rootfs.img /opt/pxemanager/defaults/coreos-rootfs.img
COPY builder.ign /opt/pxemanager/defaults/builder.ign
COPY live-builder.ign /opt/pxemanager/defaults/live-builder.ign

EXPOSE 69/udp
EXPOSE 80/tcp

CMD in.tftpd -L -s /tftpboot & exec pxemanager
