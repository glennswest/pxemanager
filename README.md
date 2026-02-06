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
# Local build
go build -o pxemanager .

# Cross-compile for ARM64 (MikroTik)
GOOS=linux GOARCH=arm64 go build -o pxemanager-arm64 .
```

### Deploy

```bash
# Deploy to MikroTik container
./deploy.sh
```

### Configuration

The application uses environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |

Database is stored in `pxemanager.db` (SQLite).

## Web UI

Access the web interface at `http://<host>:8080/`

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
├── templates/
│   ├── index.html       # Main page with HTMX
│   ├── hosts_table.html # Hosts table partial
│   ├── images_table.html# Images table partial
│   ├── ipmi_table.html  # IPMI config table
│   ├── activity_log.html# Activity log partial
│   └── host_detail.html # Host detail modal
├── deploy.sh            # Build and deploy script
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

## Development

### Running Locally

```bash
# Create test database and images
mkdir -p /tftpboot

# Run
go run main.go
```

### Adding New Image Types

**Linux kernel/initrd:**
1. Add kernel/initrd to `/tftpboot/`
2. Create image via API or UI with type `linux`
3. Configure append parameters

**ISO images:**
1. Host ISO on HTTP server (e.g., `http://fastregistry.gw.lo/isos/`)
2. Add via API: `POST /api/image/iso name=myiso&url=http://...`
3. Or add via UI: Images tab → type `iso` → enter URL

**Memdisk (floppy/small ISO):**
1. Use type `memdisk` for images loaded entirely into RAM
2. Requires memdisk binary in kernel field

## License

MIT License
