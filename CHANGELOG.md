# Changelog

## [0.9.0] - 2026-02-24

### Added
- Fedora CoreOS `coreos-builder` image — PXE installs CoreOS to disk with Ignition config
- Dual serial console support (ttyS0 Dell + ttyS1 Supermicro) in CoreOS builder
- Ignition config (`builder.ign`) with SSH key auth, podman socket, cockpit, buildah/skopeo via rpm-ostree first-boot layering
- Butane source config (`builder.bu`) for maintainable Ignition editing
- CoreOS PXE files (kernel, initramfs, rootfs) auto-downloaded in build.sh from Fedora CoreOS stable stream
- README: comprehensive section on adding images and setting up boot profiles (linux, ISO, CoreOS/Ignition, kickstart)

### Changed
- `boot_local_after` auto-set now covers CoreOS images (not just Fedora kickstart images)

### Fixed
- Root password unlocked on all images (was `--lock`) — Cockpit dashboard requires password auth
- Cockpit firewall port (9090/tcp) opened on fedora43 server kickstart
- Cockpit package and socket enabled on fedora43 server kickstart
- Builder kickstart: replaced `autopart` with explicit partitions (1G /boot, 4G swap, rest to /) — autopart was creating huge swap leaving no space for container images
- CoreOS builder.ign: removed `sudo` from core user groups — group doesn't exist on Fedora CoreOS, caused Ignition to fail silently (no users, SSH, or services configured)

## [0.8.0] - 2026-02-24

### Added
- Fedora 43 Server autoinstall image with kickstart (`fedora-ks.cfg`)
- PXE boot files for Fedora 43 (vmlinuz + initrd.img) baked into container image
- Kickstart config: SSH key auth only, autopart on sda, standard server packages, serial console for IPMI SOL
- Default `fedora43` image auto-created in database on startup

### Fixed
- Fedora PXE boot: added `inst.stage2` to kernel args (Anaconda needs stage2 image URL to boot installer)

### Added
- `fedora43-builder` image: minimal Fedora with podman/buildah/skopeo + SSH only, no docs, no LVM, no extras

### Fixed
- Fedora images now set `boot_local_after` so IPMI switches to disk boot after installer completes (prevents PXE loop)
- Builder kickstart: removed `--nodefaults` entirely (Fedora 43 Anaconda doesn't support it at all — not inline, not on `%packages` header)

## [0.7.4] - 2026-02-24

### Added
- UEFI PXE boot support — `snponly.efi` (as `ipxe.efi`) baked into image alongside `undionly.kpxe`
- Dockerfile.ipxe builds BIOS (`undionly.kpxe`), EFI (`ipxe.efi`), and SNP-only (`snponly.efi`) binaries
- Dual serial console support — kernel args include both `ttyS0` (Dell iDRAC) and `ttyS1` (Supermicro)

### Fixed
- Dell/UEFI servers (server30) can now PXE boot — microdns serves `ipxe.efi` to UEFI clients via DHCP option 93 detection
- Use `snponly.efi` for UEFI PXE — reuses firmware NIC driver instead of loading its own (fixes Dell R730xd)

### Changed
- Registry URL updated from `192.168.200.2:5000` to `registry.gt.lo:5000`

## [0.7.3] - 2026-02-23

### Added
- IPMI power cycle end-to-end test script (`scripts/test-ipmi-cycle.sh`) — exercises power off, power on, restart via pxemanager API with status polling and ipmiserial console log rotation verification

## [0.7.2] - 2026-02-23

### Fixed
- BMH sync no longer overwrites `current_image` on existing hosts — user selections now persist across sync cycles
- IPMI power on/off/restart no longer blocks waiting for ipmiserial console log rotation (moved to background goroutine)
- All iPXE chain/boot URLs use DNS (`pxe.g10.lo`) instead of hardcoded IP — works when container IP changes
- embed.ipxe, boot.ipxe, handleBootIPXE, and kernel/initrd httpBase all use `pxe.g10.lo`
- Boot file sync now checksums existing files and replaces them when the image has newer versions

### Added
- DHCP reservation test script (`scripts/test-dhcp-reservation.sh`)

## [0.7.0] - 2026-02-23

### Fixed
- Power on/restart now boots from local disk when image is `localboot` (was always forcing PXE)
- Filtered out duplicate `serverXb` devices from g10 namespace

### Changed
- BMH discovery scoped to `g10` namespace (no longer fetches all namespaces)
- Default HTTP port changed from 8080 to 80
- iPXE chain URLs updated to use port 80
- Switched to local cross-compile + alpine container build (removed golang builder stage)
- Simplified build.sh and deploy.sh to use `:edge` tag with registry poll
- Pod manifest uses `:edge` image tag for auto-updates via mkube

## [0.5.0] - 2026-01-30

### Changed
- Removed MAC address column from hosts table
- Hostname now clickable to show host detail modal
- Activity Log moved below Hosts table (no longer separate tab)
- Cleaner three-tab layout (Hosts, IPMI Config, Images)

### Added
- Host detail modal with full information
- Asset data table for hardware info from baremetalservices
- API endpoint for baremetalservices to report hardware info (POST /api/asset?mac=XX)
- Delete host button in detail modal

## [0.4.1] - 2026-01-30

### Fixed
- Fixed IPMI boot device constant (BootDeviceSelectorForceHardDrive)

## [0.4.0] - 2026-01-30

### Changed
- IPMI now uses native Go library (goipmi) - no external ipmitool needed
- Auto-configure uses short hostname + .g11.lo pattern
- Test button shows visual feedback (OK/Failed badges)

### Removed
- Dependency on external ipmitool binary

## [0.3.0] - 2026-01-30

### Changed
- Complete UI redesign with tabbed interface (Hosts, IPMI Config, Images, Activity Log)
- IPMI Config moved to separate tab with database-style editable grid
- Simplified hosts table - removed inline config, cleaner layout
- Removed "Add Host" section (hosts discovered via API)
- Removed confusing hostname.g11.lo placeholder

### Added
- IPMI test button to verify connectivity
- Proper tab navigation

## [0.2.0] - 2026-01-30

### Added
- IPMI integration with power control (On/Off/Restart)
- IPMI auto-configuration based on hostname.g11.lo pattern
- Power state display in hosts table
- IPMI configuration grid with per-host settings
- Activity logging panel with real-time updates
- Erase drive workflow engine (erase boot drive / erase all drives)
- Boot-local-after feature (auto-set IPMI to boot from disk)
- Console server integration with log rotation
- Configurable boot images (add/edit/delete via UI)
- Image flags: erase_boot_drive, erase_all_drives, boot_local_after
- Hostname lookup via DNS/DHCP
- Bulk actions: Auto-Configure All IPMI, Lookup Hostnames
- Version display in UI header
- Deploy script for ARM64/MikroTik

### Changed
- Simplified host actions (removed BIOS/OCP presets)
- Combined host config form (hostname + IPMI settings)
- Console button now works with MAC address if hostname unknown

### Removed
- biosupdate default image

## [0.1.0] - 2026-01-29

### Added
- Initial release
- Basic PXE boot management
- Host registration and image assignment
- Boot cycle support
- HTMX-based web UI
