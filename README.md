# PXE Manager

A lightweight PXE boot manager with HTMX web UI, IPMI integration, and Redfish API for OpenShift Bare Metal Operator compatibility. Designed to run on ARM64 devices like MikroTik RouterOS containers.

## Features

- **Web UI**: Real-time HTMX-based interface for managing hosts and boot images
- **Multi-NIC Support**: Track multiple network interfaces per host with selective PXE boot
- **IPMI Control**: Pure Go IPMI implementation for power management (no ipmitool required)
- **Redfish API**: OpenShift Bare Metal Operator compatible REST API
- **Virtual Media**: Mount ISOs via Redfish for OS installation
- **Activity Logging**: Real-time activity tracking with instant UI updates
- **Console Integration**: Automatic log rotation on console server
- **Boot Cycling**: Automated multi-step boot sequences (BIOS update, disk wipe, etc.)

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
│  Web UI (HTMX)  │  Redfish API  │  iPXE Handler  │  IPMI Client │
├─────────────────────────────────────────────────────────────────┤
│                      SQLite Database                             │
└─────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
    ┌─────────┐         ┌──────────┐        ┌───────────┐
    │ Browser │         │ OpenShift│        │  Servers  │
    │   UI    │         │   BMO    │        │  (iPXE)   │
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
    kernel TEXT NOT NULL,
    initrd TEXT,
    append TEXT,
    type TEXT DEFAULT 'linux',          -- linux, local, memdisk
    erase_boot_drive BOOLEAN DEFAULT 0,
    erase_all_drives BOOLEAN DEFAULT 0,
    boot_local_after BOOLEAN DEFAULT 0  -- Set IPMI to boot disk after
);
```

#### iPXE Boot Flow

1. Server PXE boots, loads `undionly.kpxe` from TFTP
2. Embedded script chains to `http://<pxemanager>/ipxe?mac=${net0/mac}`
3. PXE Manager looks up host by MAC (checking interfaces table)
4. Returns iPXE script with kernel, initrd, and append parameters
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

## Redfish API

The Redfish API provides OpenShift Bare Metal Operator compatibility.

### Service Root

```bash
GET /redfish/v1
```

```json
{
  "@odata.type": "#ServiceRoot.v1_5_0.ServiceRoot",
  "@odata.id": "/redfish/v1",
  "Id": "RootService",
  "Name": "PXE Manager Redfish Service",
  "RedfishVersion": "1.6.0",
  "Systems": {"@odata.id": "/redfish/v1/Systems"}
}
```

### Systems Collection

```bash
GET /redfish/v1/Systems
```

```json
{
  "@odata.type": "#ComputerSystemCollection.ComputerSystemCollection",
  "Members": [
    {"@odata.id": "/redfish/v1/Systems/server1"},
    {"@odata.id": "/redfish/v1/Systems/server2"}
  ],
  "Members@odata.count": 2
}
```

### Individual System

```bash
GET /redfish/v1/Systems/server1
```

```json
{
  "@odata.type": "#ComputerSystem.v1_13_0.ComputerSystem",
  "@odata.id": "/redfish/v1/Systems/server1",
  "Id": "server1",
  "Name": "server1",
  "PowerState": "On",
  "Boot": {
    "BootSourceOverrideEnabled": "Once",
    "BootSourceOverrideTarget": "Pxe",
    "BootSourceOverrideTarget@Redfish.AllowableValues": ["None", "Pxe", "Hdd"]
  },
  "Actions": {
    "#ComputerSystem.Reset": {
      "target": "/redfish/v1/Systems/server1/Actions/ComputerSystem.Reset",
      "ResetType@Redfish.AllowableValues": ["On", "ForceOff", "ForceRestart", "PushPowerButton"]
    }
  }
}
```

### Power Control

```bash
# Power on
POST /redfish/v1/Systems/server1/Actions/ComputerSystem.Reset
Content-Type: application/json
{"ResetType": "On"}

# Power off
POST /redfish/v1/Systems/server1/Actions/ComputerSystem.Reset
{"ResetType": "ForceOff"}

# Restart
POST /redfish/v1/Systems/server1/Actions/ComputerSystem.Reset
{"ResetType": "ForceRestart"}
```

### Set Boot Device

```bash
PATCH /redfish/v1/Systems/server1
Content-Type: application/json
{
  "Boot": {
    "BootSourceOverrideTarget": "Pxe",
    "BootSourceOverrideEnabled": "Once"
  }
}
```

### Virtual Media (ISO Mount)

```bash
# List virtual media
GET /redfish/v1/Systems/server1/VirtualMedia

# Get CD device
GET /redfish/v1/Systems/server1/VirtualMedia/CD1

# Mount ISO
POST /redfish/v1/Systems/server1/VirtualMedia/CD1/Actions/VirtualMedia.InsertMedia
Content-Type: application/json
{
  "Image": "http://fileserver/rhcos-live.iso",
  "Inserted": true,
  "WriteProtected": true
}

# Eject ISO
POST /redfish/v1/Systems/server1/VirtualMedia/CD1/Actions/VirtualMedia.EjectMedia
```

### Thermal Data

```bash
GET /redfish/v1/Systems/server1/Thermal
```

```json
{
  "@odata.type": "#Thermal.v1_6_0.Thermal",
  "Temperatures": [
    {"Name": "CPU Temp", "ReadingCelsius": 45, "Status": {"Health": "OK"}}
  ],
  "Fans": [
    {"Name": "Fan 1", "Reading": 5400, "ReadingUnits": "RPM"}
  ]
}
```

### Power Data

```bash
GET /redfish/v1/Systems/server1/Power
```

```json
{
  "@odata.type": "#Power.v1_6_0.Power",
  "PowerSupplies": [
    {"Name": "PSU 1", "PowerOutputWatts": 450, "Status": {"Health": "OK"}}
  ],
  "PowerControl": [
    {"Name": "System Power", "PowerConsumedWatts": 285}
  ]
}
```

## OpenShift Bare Metal Operator Setup

### Prerequisites

1. OpenShift cluster with Bare Metal Operator installed
2. PXE Manager accessible from the cluster
3. RHCOS images served via HTTP

### Create BMC Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: server1-bmc-secret
  namespace: openshift-machine-api
type: Opaque
data:
  username: YWRtaW4=      # base64 encoded: admin
  password: cGFzc3dvcmQ=  # base64 encoded: password
```

### Create BareMetalHost

```yaml
apiVersion: metal3.io/v1alpha1
kind: BareMetalHost
metadata:
  name: server1
  namespace: openshift-machine-api
spec:
  online: true
  bootMACAddress: ac:1f:6b:8a:a7:9c

  bmc:
    address: redfish-virtualmedia://pxe.example.com:8080/redfish/v1/Systems/server1
    credentialsName: server1-bmc-secret
    disableCertificateVerification: true

  rootDeviceHints:
    deviceName: /dev/sda

  # For automated provisioning
  automatedCleaningMode: disabled
```

### Complete BareMetalHost with Provisioning

```yaml
apiVersion: metal3.io/v1alpha1
kind: BareMetalHost
metadata:
  name: server1
  namespace: openshift-machine-api
  labels:
    cluster.example.com/cluster-name: my-cluster
spec:
  online: true
  bootMACAddress: ac:1f:6b:8a:a7:9c

  bmc:
    address: redfish-virtualmedia://pxe.example.com:8080/redfish/v1/Systems/server1
    credentialsName: server1-bmc-secret
    disableCertificateVerification: true

  bootMode: UEFI   # or legacy

  rootDeviceHints:
    deviceName: /dev/sda
    # Or use WWN:
    # wwn: "0x50014ee2b5e3a1c0"

  # Automated cleaning (disk wipe before provisioning)
  automatedCleaningMode: metadata  # or "disabled"

  # Custom deploy kernel/ramdisk (optional)
  # preprovisioningNetworkDataName: server1-network

  # For inspection data
  hardwareProfile: ""

  # Image to provision (for manual provisioning)
  image:
    url: http://fileserver/rhcos-live.iso
    checksum: sha256:abc123...
    checksumType: sha256
    format: live-iso
```

### Provisioning with Cluster API

```yaml
apiVersion: cluster.x-k8s.io/v1beta1
kind: Machine
metadata:
  name: server1
  namespace: openshift-machine-api
  labels:
    cluster.x-k8s.io/cluster-name: my-cluster
spec:
  clusterName: my-cluster
  infrastructureRef:
    apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
    kind: Metal3Machine
    name: server1
  bootstrap:
    configRef:
      apiVersion: bootstrap.cluster.x-k8s.io/v1beta1
      kind: KubeadmConfig
      name: server1-bootstrap
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta1
kind: Metal3Machine
metadata:
  name: server1
  namespace: openshift-machine-api
spec:
  image:
    url: http://fileserver/rhcos-live.iso
    checksum: sha256:abc123...
    checksumType: sha256
    format: live-iso
  hostSelector:
    matchLabels:
      cluster.example.com/cluster-name: my-cluster
```

### Agent-Based Installation

For OpenShift Agent-Based Installer:

```yaml
apiVersion: agent-install.openshift.io/v1beta1
kind: InfraEnv
metadata:
  name: my-cluster
  namespace: my-cluster
spec:
  pullSecretRef:
    name: pull-secret
  sshAuthorizedKey: "ssh-rsa AAAA..."
  nmStateConfigLabelSelector:
    matchLabels:
      cluster: my-cluster
---
apiVersion: agent-install.openshift.io/v1beta1
kind: NMStateConfig
metadata:
  name: server1
  namespace: my-cluster
  labels:
    cluster: my-cluster
spec:
  config:
    interfaces:
      - name: eno1
        type: ethernet
        state: up
        ipv4:
          enabled: true
          dhcp: true
  interfaces:
    - name: eno1
      macAddress: "AC:1F:6B:8A:A7:9C"
---
apiVersion: metal3.io/v1alpha1
kind: BareMetalHost
metadata:
  name: server1
  namespace: my-cluster
  labels:
    infraenvs.agent-install.openshift.io: my-cluster
spec:
  online: true
  bootMACAddress: ac:1f:6b:8a:a7:9c
  bmc:
    address: redfish-virtualmedia://pxe.example.com:8080/redfish/v1/Systems/server1
    credentialsName: server1-bmc-secret
    disableCertificateVerification: true
  automatedCleaningMode: disabled
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

### Redfish endpoints returning errors

1. Verify host has hostname and IPMI configured
2. Check `/redfish/v1/Systems` lists the host
3. Test IPMI directly first

## Development

### Running Locally

```bash
# Create test database and images
mkdir -p /tftpboot

# Run
go run main.go
```

### Adding New Image Types

1. Add kernel/initrd to `/tftpboot/`
2. Create image via API or UI
3. Configure boot parameters

### Extending Redfish

Add new handlers in `main.go`:

```go
// Add to handleRedfishSystemRouter
case subPath == "NewEndpoint":
    handleRedfishNewEndpoint(w, r, hostname)
```

## License

MIT License
