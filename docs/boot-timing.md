# Boot Timing Comparison

## Test Environment
- **Server**: server1 (Supermicro X9SRD-F, Xeon E5-2651 v2, 64GB DDR3)
- **Network**: 10GbE to switch, MikroTik Rose (100GbE uplinks)
- **PXE Server**: 192.168.10.200 (ARM64, MikroTik container)
- **Date**: 2026-02-25

---

## Method 1: Standard PXE + CoreOS (current)

Stock undionly.kpxe, HTTP downloads from pxemanager.

| Stage | Time | Duration | Notes |
|-------|------|----------|-------|
| Power on -> BIOS POST complete | | | |
| BIOS POST -> PXE/DHCP start | | | |
| DHCP + iPXE chain load | | | iPXE loads from TFTP, chains to pxemanager |
| Download coreos-kernel (~10MB) | | | HTTP from pxemanager |
| Download coreos-initramfs (~80MB) | | | HTTP from pxemanager |
| Kernel boot + initramfs decompress | | | |
| Download coreos-rootfs.img (~900MB) | | | HTTP, fetched by initramfs |
| coreos-installer write to disk | | | Writing ~2GB to SSD/HDD |
| Reboot #1 (installer done) | | | |
| GRUB -> kernel boot | | | |
| Ignition first boot (kernelArgs) | | | Adds serial console args |
| Reboot #2 (kernelArgs applied) | | | |
| rpm-ostree install (cockpit, buildah, skopeo) | | | Downloads + layers packages |
| Reboot #3 (rpm-ostree done) | | | |
| Final boot -> SSH available | | | |
| **Total: Power on -> SSH ready** | | | |

### Bottlenecks
- Rootfs download (~900MB over HTTP)
- rpm-ostree package layering (network download + ostree compose)
- 3 reboots

---

## Method 2: Custom iPXE + HTTP (planned)

Custom iPXE with TCP 128MB window, 1MB read-ahead cache, jumbo frames.

| Stage | Time | Duration | Notes |
|-------|------|----------|-------|
| Power on -> BIOS POST complete | | | Same as Method 1 |
| DHCP + custom iPXE chain load | | | Custom undionly.kpxe |
| Download coreos-kernel (~10MB) | | | HTTP with TCP tuning |
| Download coreos-initramfs (~80MB) | | | HTTP with TCP tuning |
| Kernel boot + initramfs decompress | | | Same |
| Download coreos-rootfs.img (~900MB) | | | HTTP with TCP tuning + cache |
| coreos-installer write to disk | | | Same |
| Reboot -> final SSH ready | | | Same reboot sequence |
| **Total: Power on -> SSH ready** | | | |

### Expected Improvements
- Faster HTTP downloads (TCP window scaling, jumbo frames)
- Read-ahead cache reduces round-trips for rootfs
- Same reboot count (3)

---

## Method 3: iSCSI Sanboot (planned)

ISO served as iSCSI LUN from Rose server. Zero download -- blocks read on demand.

| Stage | Time | Duration | Notes |
|-------|------|----------|-------|
| Power on -> BIOS POST complete | | | Same |
| DHCP + iPXE chain load | | | Custom iPXE with iSCSI |
| iSCSI target connect | | | `sanboot iscsi:<rose-ip>::::<iqn>` |
| ISO boot (no download) | | | Blocks read over network on demand |
| Installer runs (if install image) | | | Or live boot directly |
| **Total: Power on -> usable** | | | |

### Expected Improvements
- No 900MB rootfs download (blocks read on demand)
- Near-instant boot after iSCSI connect
- Best for live/installer ISOs
- Network I/O spread across boot instead of upfront bulk download

---

## Comparison Summary

| Metric | Standard PXE | Custom iPXE | iSCSI Sanboot |
|--------|-------------|-------------|---------------|
| Kernel+initramfs download | | | N/A (in ISO) |
| Rootfs/ISO download | ~900MB upfront | ~900MB (faster) | 0 (on-demand) |
| Time to first kernel | | | |
| Time to installer | | | |
| Time to SSH ready | | | |
| Total reboots | 3 | 3 | 0-1 |
| Network bandwidth used | ~1GB | ~1GB | Variable |
| Works offline after boot | Yes | Yes | No (needs iSCSI) |

---

## How to Measure

### From ipmiserial console
The serial console output includes timestamps. Watch for these markers:
- `iPXE initialising devices...` — iPXE started
- `http://pxe.g10.lo/files/coreos-kernel... ok` — kernel downloaded
- `http://pxe.g10.lo/files/coreos-initramfs... ok` — initramfs downloaded
- `Booting coreos-builder` — kernel handoff
- `coreos-installer install` — installer started (in journal)
- `Booting 'Fedora CoreOS'` — GRUB after install
- Login prompt or SSH responding — final ready

### Timing SSH availability
```bash
# Run this before power-on, it polls every 2 seconds
time while ! ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no core@server1.g10.lo true 2>/dev/null; do sleep 2; done; echo "SSH READY"
```
