# PXE Manager

A lightweight PXE boot manager with HTMX web UI, IPMI integration, and Redfish API for OpenShift Bare Metal Operator compatibility. Designed to run on ARM64 devices like MikroTik RouterOS containers.

## Features

- **Web UI**: Real-time HTMX-based interface for managing hosts and boot images
- **Multi-NIC Support**: Track multiple network interfaces per host with selective PXE boot
- **IPMI Control**: Pure Go IPMI implementation for power management (no ipmitool required)
- **ISO Boot**: Boot directly from remote ISO URLs via iPXE sanboot
- **Activity Logging**: Real-time activity tracking with instant UI updates
- **Console Integration**: Automatic log rotation on console server
- **Boot Cycling**: Automated multi-step boot sequences (BIOS update, disk wipe, etc.)
- **REST API**: Full API for automation and integration

## Infrastructure

### Network Services

| Service | Host | Description |
|---------|------|-------------|
| DNS | `root@dnsx.gw.lo` | PowerDNS authoritative DNS server |
| DHCP | `root@rose1.gw.lo` | MikroTik router with DHCP reservations |
| PXE Manager | `pxe.gw.lo` | This application |
| Console Server | `console.g11.lo` | Serial console log server |

### IPMI Network Convention

- IPMI/BMC addresses follow pattern: `{hostname}.g11.lo`
- Example: server3 → IPMI at `server3.g11.lo`
- Default credentials: `ADMIN/ADMIN`

### Hostname Resolution

Hostnames are resolved via the Network Manager API:
1. **Network Manager API** - `http://network.gw.lo/api/hosts` returns all hosts with MAC→hostname mapping
2. **Manual configuration** - Set hostname directly in PXE Manager UI

The Network Manager aggregates data from:
- MikroTik DHCP reservations (rose1.gw.lo)
- PowerDNS records (dnsx.gw.lo)

### Network Manager Scan API

Trigger scans to refresh host data:

```bash
# Refresh DHCP leases from MikroTik
curl -X POST http://network.gw.lo/api/scan/dhcp

# Refresh DNS records from PowerDNS
curl -X POST http://network.gw.lo/api/scan/dns

# Ping scan to check online status
curl -X POST http://network.gw.lo/api/scan/ping

# Switch scan (MAC table discovery)
curl -X POST http://network.gw.lo/api/scan/switch
```

### Adding a New Server

1. Create DHCP reservation on rose1.gw.lo (MikroTik)
2. Add DNS A record on dnsx.gw.lo (PowerDNS)
3. Add IPMI DNS record: `{hostname}.g11.lo` pointing to BMC IP
4. Server auto-registers on first PXE boot
5. Click "Lookup Hostnames" or manually set hostname in UI
6. Click "Auto Configure IPMI" to set IPMI address

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         PXE Manager                              │
├─────────────────────────────────────────────────────────────────┤
│  Web UI (HTMX)  │  REST API  │  iPXE Handler  │  IPMI Client    │
├─────────────────────────────────────────────────────────────────┤
│                      SQLite Database                             │
└─────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
    ┌─────────┐         ┌──────────┐        ┌───────────┐
    │ Browser │         │ Scripts/ │        │  Servers  │
    │   UI    │         │ Automation│       │  (iPXE)   │
    └─────────┘         └──────────┘        └───────────┘
```

## Quick Start

### Prerequisites

- Go 1.21+
- DHCP server configured to serve iPXE (next-server pointing to PXE Manager)
- TFTP server with `undionly.kpxe` (or use built-in HTTP boot)

### Build

```bash
# Build app image only (~13 MB, fast)
./build.sh

# Build data image only (~1.3 GB, large boot files — only when kernels/rootfs change)
./build.sh --data

# Build both
./build.sh --all
```

### Deploy

```bash
# Deploy app image (fast, code-only changes)
./deploy.sh

# Deploy data image (large boot files changed)
./deploy.sh --data

# Deploy both
./deploy.sh --all
```

### Configuration

The application uses environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `80` | HTTP server port |
| `REGISTRY_URL` | `http://registry.gt.lo:5000` | Container registry for pulling data image |

Database is stored in `pxemanager.db` (SQLite).

## Web UI

Access the web interface at `http://<host>/`

### Tabs

1. **Hosts**: View all registered hosts, power state, current image, and actions
2. **IPMI Config**: Configure IPMI credentials for each host
3. **Images**: Manage boot images (kernel, initrd, append parameters)

### Host Actions

- **Power On/Off/Restart**: IPMI power control with automatic PXE boot device setting
- **Image Selection**: Dropdown to change current boot image
- **Console**: Link to serial console server

## Code Structure

```
pxemanager/
├── main.go              # Main application (all handlers)
├── Dockerfile           # App image (~13 MB) — binary + small configs
├── Dockerfile.data      # Data image (~1.3 GB) — kernels + rootfs
├── build.sh             # Build script (--data for data image)
├── deploy.sh            # Build + push (--data for data image)
├── templates/
│   ├── index.html       # Main page with HTMX
│   ├── hosts_table.html # Hosts table partial
│   ├── images_table.html# Images table partial
│   ├── ipmi_table.html  # IPMI config table
│   ├── activity_log.html# Activity log partial
│   └── host_detail.html # Host detail modal
├── boot.ipxe            # iPXE boot script
├── embed.ipxe           # Embedded iPXE script
└── undionly-custom.kpxe # Custom iPXE with embedded script
```

### Key Components

#### Database Schema

```sql
-- Hosts table
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    mac TEXT UNIQUE NOT NULL,
    hostname TEXT,
    current_image TEXT DEFAULT 'baremetalservices',
    next_image TEXT,                    -- One-shot boot override
    cycle_images TEXT,                  -- JSON array for boot cycles
    last_boot DATETIME,
    boot_count INTEGER DEFAULT 0,
    ipmi_ip TEXT,
    ipmi_username TEXT DEFAULT 'ADMIN',
    ipmi_password TEXT DEFAULT 'ADMIN',
    virtual_media_url TEXT,             -- Mounted ISO URL
    created DATETIME
);

-- Host interfaces (multi-NIC support)
CREATE TABLE host_interfaces (
    id INTEGER PRIMARY KEY,
    host_id INTEGER,
    mac TEXT UNIQUE NOT NULL,
    name TEXT,                          -- 'a' for primary, 'b' for secondary
    hostname TEXT,                      -- FQDN for this interface
    use BOOLEAN DEFAULT 1               -- Enable/disable PXE on this interface
);

-- Boot images
CREATE TABLE images (
    name TEXT PRIMARY KEY,
    kernel TEXT NOT NULL,               -- For ISO type, this contains the full URL
    initrd TEXT,
    append TEXT,
    type TEXT DEFAULT 'linux',          -- linux, iso, local, memdisk
    erase_boot_drive BOOLEAN DEFAULT 0,
    erase_all_drives BOOLEAN DEFAULT 0,
    boot_local_after BOOLEAN DEFAULT 0  -- Set IPMI to boot disk after
);
```

#### iPXE Boot Flow

1. Server PXE boots, loads `undionly.kpxe` from TFTP
2. Embedded script chains to `http://<pxemanager>/ipxe?mac=${net0/mac}`
3. PXE Manager looks up host by MAC (checking interfaces table)
4. Returns iPXE script based on image type:
   - **linux**: kernel + initrd + append parameters
   - **iso**: `sanboot <url>` to boot directly from ISO
   - **memdisk**: kernel with memdisk for floppy/ISO images
   - **local**: `exit` to boot from local disk
5. If `next_image` is set, uses it once then clears
6. If `cycle_images` is set, advances through the cycle

#### IPMI Functions

```go
// Power control
ipmiPowerOn(host *Host) error      // Power on + set PXE boot
ipmiPowerOff(host *Host) error     // Power off
ipmiRestart(host *Host) error      // Power cycle + set PXE boot

// Boot device
ipmiSetBootPXE(host *Host) error   // Set next boot to PXE
ipmiSetBootDisk(host *Host) error  // Set next boot to disk

// Status
ipmiPowerStatus(host *Host) (string, error)  // Returns "on" or "off"
```

## API Reference

### Host Management

```bash
# List all hosts
GET /api/hosts

# Get host interfaces
GET /api/host/interfaces?host_id=1

# Update interface (enable/disable PXE)
POST /api/host/interface?action=update
     id=1&name=a&hostname=server1.example.com&use=true
```

### IPMI Control

```bash
# Power actions (uses hostname, not MAC)
POST /api/host/ipmi?host=server1&action=power_on
POST /api/host/ipmi?host=server1&action=power_off
POST /api/host/ipmi?host=server1&action=restart

# Get power status
GET /api/host/ipmi/status?host=server1

# Configure IPMI credentials
POST /api/host/ipmi/config?host=server1
     ipmi_ip=server1-ipmi.example.com&ipmi_username=admin&ipmi_password=secret
```

### Images

```bash
# List images
GET /api/images

# Add image
POST /api/image/add
     name=rhcos&kernel=/files/rhcos-kernel&initrd=/files/rhcos-initrd&append=coreos.live.rootfs_url=...

# Update image
POST /api/image/update
     name=rhcos&kernel=...&erase_boot_drive=true&boot_local_after=true

# Delete image
POST /api/image/delete?name=oldimage
```

### ISO Images

Add ISO images that boot directly from a URL via iPXE `sanboot`:

```bash
# Add an ISO image (appears as selectable boot target)
POST /api/image/iso
     name=rhel9-installer&url=http://fastregistry.gw.lo/isos/rhel9.iso

# List all ISO images
GET /api/image/iso

# Response:
[
  {"name": "rhel9-installer", "url": "http://fastregistry.gw.lo/isos/rhel9.iso"},
  {"name": "ubuntu-22.04", "url": "http://fastregistry.gw.lo/isos/ubuntu-22.04.iso"}
]
```

ISO images can also be added via the Web UI:
1. Go to **Images** tab
2. Select type **iso** from dropdown
3. Enter name and full ISO URL
4. Click **Add Image**

When a host boots an ISO image, the generated iPXE script uses:
```
#!ipxe
echo Booting rhel9-installer for server1 (aa:bb:cc:dd:ee:ff)
sanboot http://fastregistry.gw.lo/isos/rhel9.iso
```

## Baremetalservices Integration

PXE Manager integrates with `baremetalservices` running on booted hosts for:

### IPMI Reset to DHCP

```bash
# Reset IPMI to DHCP (useful for initial setup)
POST /api/host/baremetal/reset-ipmi?host=server1
     username=ADMIN&password=ADMIN
```

### MAC Address Discovery

```bash
# Get all MAC addresses from a running host
GET /api/host/baremetal/get-macs?host=server1

# Response:
{
  "eth0": "aa:bb:cc:dd:ee:f0",
  "eth1": "aa:bb:cc:dd:ee:f1",
  "ipmi": "aa:bb:cc:dd:ee:f2"
}

# Auto-discover and register all interfaces
POST /api/host/baremetal/auto-discover?host=server1
```

## DHCP Configuration

### dnsmasq Example

```conf
# Enable TFTP
enable-tftp
tftp-root=/tftpboot

# PXE boot
dhcp-boot=undionly.kpxe,,192.168.10.200

# Or for UEFI:
# dhcp-match=set:efi-x86_64,option:client-arch,7
# dhcp-boot=tag:efi-x86_64,ipxe.efi,,192.168.10.200
```

### MikroTik RouterOS

```
/ip dhcp-server network
set 0 next-server=192.168.10.200 boot-file-name=undionly.kpxe
```

## Console Server Integration

PXE Manager integrates with a console server for serial log management:

```bash
# Rotate console logs on power events
POST http://console.example.com/api/servers/{hostname}/logs/rotate?name={label}
```

Log labels are automatically generated:
- Power on: `{imagename}-{YYYYMMDD-HHMMSS}`
- Power off: `unused-{YYYYMMDD-HHMMSS}`

## Troubleshooting

### Host not PXE booting

1. Check DHCP is providing correct next-server and boot file
2. Verify host interface is enabled: `GET /api/host/interfaces?host_id=X`
3. Check activity log for boot attempts
4. Verify TFTP/HTTP accessibility from host network

### IPMI not working

1. Test IPMI connectivity from PXE Manager host
2. Verify credentials in IPMI Config tab
3. Check activity log for IPMI errors
4. Ensure IPMI is on accessible network

### ISO not booting

1. Verify ISO URL is accessible from the booting host
2. Check iPXE supports the ISO format (most Linux installers work)
3. Some ISOs require memdisk instead of sanboot
4. Check activity log for boot attempts

## Images and Boot Profiles

PXE Manager supports four image types. Each image defines what a server boots into when it PXE boots.

### Image Types

| Type | Description | Use Case |
|------|-------------|----------|
| `linux` | Kernel + initrd + kernel args | OS installers, live images, CoreOS |
| `iso` | Direct HTTP ISO boot via iPXE `sanboot` | Pre-built ISOs (RHEL, Ubuntu, etc.) |
| `memdisk` | Load entire image into RAM via SYSLINUX memdisk | Floppy images, small ISOs |
| `local` | Exit iPXE, boot from local disk | Normal disk boot |

### Built-in Images

These images are auto-created on startup:

| Name | Type | Description |
|------|------|-------------|
| `baremetalservices` | linux | Discovery/management OS (dual serial ttyS0+ttyS1) |
| `localboot` | local | Boot from local disk |
| `fedora43` | linux | Fedora 43 Server kickstart install (ttyS1 serial) |
| `fedora43-builder` | linux | Fedora 43 minimal builder with podman (ttyS1 serial) |
| `coreos-builder` | linux | Fedora CoreOS builder with podman (dual serial ttyS0+ttyS1) |

### Adding a Linux Kernel/Initrd Image

1. Place kernel and initrd files in `/tftpboot/` (or bake into the container image under `/opt/pxemanager/defaults/`)
2. Add via UI: **Images** tab, type `linux`, fill in kernel filename, initrd filename, and kernel args
3. Or via API:

```bash
curl -X POST http://pxe.g10.lo/api/image/add \
  -d 'name=myimage&kernel=my-vmlinuz&initrd=my-initrd.img&append=ip=dhcp console=ttyS0,115200n8&type=linux'
```

**Image flags:**
- `boot_local_after=true` — After this image boots, set IPMI to disk boot (prevents PXE loop after installers)
- `erase_boot_drive=true` — Trigger disk wipe workflow before booting
- `erase_all_drives=true` — Wipe all drives before booting

### Adding an ISO Image

ISO images boot directly from an HTTP URL using iPXE `sanboot`:

```bash
# Via API
curl -X POST http://pxe.g10.lo/api/image/iso \
  -d 'name=rhel9&url=http://fastregistry.gw.lo/isos/rhel9.iso'

# Or via UI: Images tab → type "iso" → enter name and full URL
```

### Adding a Fedora CoreOS Image (Ignition)

CoreOS uses Ignition configs instead of kickstarts. The `coreos-builder` image is pre-configured, but you can create custom CoreOS profiles:

1. **Write an Ignition config** (JSON) or Butane config (YAML, convert with `butane`):

```yaml
# my-server.bu — convert with: butane --strict my-server.bu > my-server.ign
variant: fcos
version: "1.5.0"
passwd:
  users:
    - name: root
      ssh_authorized_keys:
        - "ssh-rsa AAAA..."
kernel_arguments:
  should_exist:
    - console=tty0
    - console=ttyS0,115200n8
systemd:
  units:
    - name: podman.socket
      enabled: true
```

2. **Place the `.ign` file** in `/tftpboot/` (it will be served at `http://pxe.g10.lo/files/my-server.ign`)

3. **Create the image** with CoreOS kernel args:

```bash
curl -X POST http://pxe.g10.lo/api/image/add \
  -d 'name=my-coreos' \
  -d 'kernel=coreos-kernel' \
  -d 'initrd=coreos-initramfs' \
  -d 'append=coreos.inst.install_dev=/dev/sda coreos.inst.ignition_url=http://pxe.g10.lo/files/my-server.ign coreos.live.rootfs_url=http://pxe.g10.lo/files/coreos-rootfs.img ip=dhcp console=tty0 console=ttyS0,115200n8' \
  -d 'type=linux' \
  -d 'boot_local_after=true'
```

**CoreOS kernel parameters:**

| Parameter | Description |
|-----------|-------------|
| `coreos.inst.install_dev=/dev/sda` | Disk to install to (triggers auto-install) |
| `coreos.inst.ignition_url=http://...` | Ignition config for the installed system |
| `coreos.live.rootfs_url=http://...` | Live rootfs image (fetched at boot, ~900MB) |
| `ip=dhcp` | Network config for live environment |
| `console=ttyS0,115200n8` | Serial console (Dell iDRAC uses ttyS0, Supermicro uses ttyS1) |

**CoreOS boot flow:**
1. iPXE loads kernel + initramfs
2. CoreOS fetches rootfs from `rootfs_url`
3. Installer writes OS to disk using metal image from rootfs
4. Ignition config is applied to the installed system
5. Server reboots → `boot_local_after` switches IPMI to disk boot
6. First disk boot: rpm-ostree layers additional packages, reboots once more
7. Ready to use

### Adding a Kickstart Image (Fedora/RHEL/CentOS)

1. **Write a kickstart config** (see `fedora-ks.cfg` or `fedora-builder-ks.cfg` as examples)
2. **Place it in `/tftpboot/`** or bake into the container
3. **Create the image** pointing to the kickstart:

```bash
curl -X POST http://pxe.g10.lo/api/image/add \
  -d 'name=my-fedora' \
  -d 'kernel=fedora-vmlinuz' \
  -d 'initrd=fedora-initrd.img' \
  -d 'append=inst.stage2=https://download.fedoraproject.org/pub/fedora/linux/releases/43/Server/x86_64/os/ inst.ks=http://pxe.g10.lo/files/my-ks.cfg ip=dhcp console=tty0 console=ttyS1,115200n8' \
  -d 'type=linux' \
  -d 'boot_local_after=true'
```

### Serial Console Reference

| Vendor | Serial Port | Kernel Arg |
|--------|-------------|------------|
| Dell (iDRAC) | ttyS0 | `console=ttyS0,115200n8` |
| Supermicro | ttyS1 | `console=ttyS1,115200n8` |
| Both (safe default) | ttyS0 + ttyS1 | `console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8` |

The last `console=` parameter is the primary console. For dual-vendor environments, include both serial ports in kernel args.

### Assigning Images to Hosts

**One-time boot** (next boot only, then reverts):
```bash
# Via API
curl -X POST 'http://pxe.g10.lo/api/host/set-image?mac=AA:BB:CC:DD:EE:FF&image=coreos-builder&next=true'

# Via UI: click host → select image from dropdown → "Next Boot"
```

**Permanent change:**
```bash
curl -X POST 'http://pxe.g10.lo/api/host/set-image?mac=AA:BB:CC:DD:EE:FF&image=coreos-builder'

# Via UI: click host → select image from dropdown → "Set Image"
```

**Boot cycle** (sequence of images):
```bash
# Boot baremetalservices first, then coreos-builder
curl -X POST 'http://pxe.g10.lo/api/host/set-cycle?mac=AA:BB:CC:DD:EE:FF' \
  -d '["baremetalservices","coreos-builder"]'
```

### Split Image Architecture

The project uses two container images to keep code-only deploys fast:

| Image | Size | Contents | Rebuild frequency |
|-------|------|----------|-------------------|
| `pxemanager:edge` | ~13 MB | Go binary, iPXE bootloaders, configs, kickstarts | Every code change |
| `pxemanager-data:edge` | ~1.3 GB | Kernels, initramfs, CoreOS rootfs | Only when boot files change |

On startup, small config files are copied from `/opt/pxemanager/defaults/` (baked into app image). Large boot files are pulled on-demand from the `pxemanager-data` image in the container registry via the Docker Registry HTTP API v2.

**Data pull behavior:**
- Checks which large files are missing from `/tftpboot/`
- Pulls layer blobs from registry, extracts only missing files
- Saves manifest digest to `.data-digest` — skips pull if unchanged on next restart
- Falls back gracefully if registry is unreachable (existing files keep working)

### Adding Custom Boot Files

For small configs (ignition, kickstart):
1. Add file to the project directory
2. Add `COPY` line to `Dockerfile` → `/opt/pxemanager/defaults/`
3. Rebuild app image: `./deploy.sh`

For large files (kernels, initrd, rootfs):
1. Add file to the project directory
2. Add `COPY` line to `Dockerfile.data` → `/data/`
3. Add filename to `dataFiles` list in `main.go`
4. Rebuild data image: `./deploy.sh --data`

## Development

### Running Locally

```bash
# Create test database and images
mkdir -p /tftpboot

# Run
go run main.go
```

## License

MIT License
