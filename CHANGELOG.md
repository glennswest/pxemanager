# Changelog

## [0.7.1] - 2026-02-23

### Fixed
- BMH sync no longer overwrites `current_image` on existing hosts — user selections now persist across sync cycles
- IPMI power on/off/restart no longer blocks waiting for ipmiserial console log rotation (moved to background goroutine)
- All iPXE chain/boot URLs use DNS (`pxe.g10.lo`) instead of hardcoded IP — works when container IP changes
- embed.ipxe, boot.ipxe, handleBootIPXE, and kernel/initrd httpBase all use `pxe.g10.lo`
- Boot file sync now checksums existing files and replaces them when the image has newer versions

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
