package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bougou/go-ipmi"
	_ "modernc.org/sqlite"
)

const ConsoleServerURL = "http://ipmiserial.g11.lo"
const NetworkManagerURL = "http://network.gw.lo"
const DefaultMkubeURL = "http://192.168.200.2:8082"
const ISCSIPortalIP = "192.168.10.1" // rose.g10.lo — iSCSI portal for g10 clients

// Version is set at build time via -ldflags
var Version = "dev"

// bmhMap tracks hostname → BMH metadata for PATCH updates to mkube
var bmhMap sync.Map // map[string]bmhObject

// activeMkubeURL is the mkube API URL used for BMH operations
var activeMkubeURL string

// PowerTransition tracks an in-progress power state change for a host.
type PowerTransition struct {
	Hostname    string
	Action      string // "power_on", "power_off", "restart"
	DesiredOn   bool   // true for power_on/restart, false for power_off
	StartedAt   time.Time
	Attempt     int
	MaxAttempts int
	Done        bool
	Failed      bool
	mu          sync.Mutex
}

// powerTransitions tracks active power transitions: hostname → *PowerTransition
var powerTransitions sync.Map

// powerStateCache caches IPMI power status per host: hostname → "on"/"off"/"unknown"
var powerStateCache sync.Map

// ipmiPowerPoller runs a background loop that polls IPMI power status for all
// hosts with IPMI configured. Updates powerStateCache and broadcasts SSE events
// when state changes. Polls every 30s normally, every 2s during transitions.
func ipmiPowerPoller() {
	for {
		// Collect hosts with IPMI
		rows, err := db.Query(`SELECT hostname, ipmi_ip, ipmi_username, ipmi_password FROM hosts WHERE ipmi_ip IS NOT NULL AND ipmi_ip != ''`)
		if err != nil {
			time.Sleep(30 * time.Second)
			continue
		}

		type ipmiHost struct {
			hostname, ip, user, pass string
		}
		var hosts []ipmiHost
		for rows.Next() {
			var h ipmiHost
			if err := rows.Scan(&h.hostname, &h.ip, &h.user, &h.pass); err == nil {
				hosts = append(hosts, h)
			}
		}
		rows.Close()

		changed := false
		for _, h := range hosts {
			// Skip hosts with active transitions — those poll faster internally
			if _, transitioning := powerTransitions.Load(h.hostname); transitioning {
				continue
			}

			host := &Host{
				Hostname:     h.hostname,
				IPMIIP:       &h.ip,
				IPMIUsername:  h.user,
				IPMIPassword: h.pass,
			}
			status, _ := ipmiPowerStatus(host)
			old, _ := powerStateCache.Load(h.hostname)
			powerStateCache.Store(h.hostname, status)
			if old != status {
				changed = true
			}
		}

		if changed {
			sseBroadcast("hostsUpdated")
		}

		time.Sleep(30 * time.Second)
	}
}

// ─── SSE Event Bus ──────────────────────────────────────────────────────────

// sseClients holds all connected SSE clients. Each client is a channel that
// receives event names (e.g. "hostsUpdated", "activityUpdated", "imagesUpdated").
var sseClients struct {
	mu      sync.Mutex
	clients map[chan string]bool
}

func init() {
	sseClients.clients = make(map[chan string]bool)
}

// sseBroadcast sends an event to all connected SSE clients.
func sseBroadcast(event string) {
	sseClients.mu.Lock()
	defer sseClients.mu.Unlock()
	for ch := range sseClients.clients {
		select {
		case ch <- event:
		default:
			// Client too slow, skip
		}
	}
}

// handleSSE serves a Server-Sent Events stream. Connected browsers receive
// instant notifications when hosts, images, or activity state changes.
func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan string, 16)
	sseClients.mu.Lock()
	sseClients.clients[ch] = true
	sseClients.mu.Unlock()

	defer func() {
		sseClients.mu.Lock()
		delete(sseClients.clients, ch)
		sseClients.mu.Unlock()
	}()

	// Send initial heartbeat so client knows connection is live
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: {}\n\n", event)
			flusher.Flush()
		}
	}
}

//go:embed templates/*
var templatesFS embed.FS

var db *sql.DB
var templates *template.Template

// Image represents a bootable image
type Image struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Kernel         string `json:"kernel"`
	Initrd         string `json:"initrd"`
	Append         string `json:"append"`
	Type           string `json:"type"` // linux, memdisk, local
	EraseBootDrive bool   `json:"erase_boot_drive"`
	EraseAllDrives bool   `json:"erase_all_drives"`
	BootLocalAfter bool   `json:"boot_local_after"`
	Created        string `json:"created"`
}

// Host represents a managed host
type Host struct {
	ID           int     `json:"id"`
	MAC          string  `json:"mac"`
	Hostname     string  `json:"hostname"`
	CurrentImage string  `json:"current_image"`
	NextImage    *string `json:"next_image"`
	CycleImages  *string `json:"cycle_images"` // JSON array of image names
	CycleIndex   int     `json:"cycle_index"`
	LastBoot     *string `json:"last_boot"`
	BootCount    int     `json:"boot_count"`
	IPMIIP       *string `json:"ipmi_ip"`
	IPMIUsername string  `json:"ipmi_username"`
	IPMIPassword string  `json:"ipmi_password"`
	ConsoleID    *string `json:"console_id"`
	Created      string  `json:"created"`
}

// ActivityLog represents an activity log entry
type ActivityLog struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"` // info, warn, error
	Category  string `json:"category"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	Message   string `json:"message"`
}

// Workflow represents a multi-step erase operation
type Workflow struct {
	ID             int     `json:"id"`
	MAC            string  `json:"mac"`
	Type           string  `json:"type"`
	State          string  `json:"state"` // pending, erasing, waiting, booting, completed, failed
	TargetImage    string  `json:"target_image"`
	EraseBootDrive bool    `json:"erase_boot_drive"`
	EraseAllDrives bool    `json:"erase_all_drives"`
	Started        string  `json:"started"`
	Updated        string  `json:"updated"`
	ErrorMessage   *string `json:"error_message"`
}

// BootLog represents a boot event
type BootLog struct {
	ID        int    `json:"id"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	Image     string `json:"image"`
	Timestamp string `json:"timestamp"`
}

// AssetData represents hardware asset information from baremetalservices
type AssetData struct {
	ID            int     `json:"id"`
	MAC           string  `json:"mac"`
	Manufacturer  string  `json:"manufacturer"`
	ProductName   string  `json:"product_name"`
	SerialNumber  string  `json:"serial_number"`
	BIOSVersion   string  `json:"bios_version"`
	TotalMemoryGB float64 `json:"total_memory_gb"`
	CPUModel      string  `json:"cpu_model"`
	CPUCount      int     `json:"cpu_count"`
	DiskInfo      string  `json:"disk_info"`
	NetworkInfo   string  `json:"network_info"`
	LastUpdated   string  `json:"last_updated"`
}

// HostInterface represents a network interface on a host (servers have multiple)
type HostInterface struct {
	ID       int    `json:"id"`
	HostID   int    `json:"host_id"`
	MAC      string `json:"mac"`
	Name     string `json:"name"` // e.g., "a", "b", "primary", "secondary"
	Hostname string `json:"hostname"` // e.g., server1a.g10.lo, server1b.g10.lo
	Use      bool   `json:"use"` // whether to allow PXE boot from this interface
	Created  string `json:"created"`
}

func initDB() error {
	var err error
	dbPath := os.Getenv("PXEMANAGER_DB")
	if dbPath == "" {
		dbPath = "/var/lib/pxemanager/pxemanager.db"
	}

	// Ensure directory exists
	if err := os.MkdirAll("/var/lib/pxemanager", 0755); err != nil {
		// Try current directory as fallback
		dbPath = "./pxemanager.db"
	}

	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS images (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		kernel TEXT NOT NULL,
		initrd TEXT,
		append TEXT,
		type TEXT DEFAULT 'linux',
		erase_boot_drive BOOLEAN DEFAULT 0,
		erase_all_drives BOOLEAN DEFAULT 0,
		boot_local_after BOOLEAN DEFAULT 0,
		created DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac TEXT UNIQUE NOT NULL,
		hostname TEXT,
		current_image TEXT DEFAULT 'baremetalservices',
		next_image TEXT,
		cycle_images TEXT,
		cycle_index INTEGER DEFAULT 0,
		last_boot DATETIME,
		boot_count INTEGER DEFAULT 0,
		ipmi_ip TEXT,
		ipmi_username TEXT DEFAULT 'ADMIN',
		ipmi_password TEXT DEFAULT 'ADMIN',
		console_id TEXT,
		virtual_media_url TEXT,
		created DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (current_image) REFERENCES images(name)
	);

	CREATE TABLE IF NOT EXISTS boot_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac TEXT NOT NULL,
		hostname TEXT,
		image TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS activity_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		level TEXT DEFAULT 'info',
		category TEXT NOT NULL,
		mac TEXT,
		hostname TEXT,
		message TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS workflows (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac TEXT NOT NULL,
		type TEXT NOT NULL,
		state TEXT NOT NULL,
		target_image TEXT NOT NULL,
		erase_boot_drive BOOLEAN DEFAULT 0,
		erase_all_drives BOOLEAN DEFAULT 0,
		started DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated DATETIME DEFAULT CURRENT_TIMESTAMP,
		error_message TEXT
	);

	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS asset_data (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac TEXT UNIQUE NOT NULL,
		manufacturer TEXT,
		product_name TEXT,
		serial_number TEXT,
		bios_version TEXT,
		total_memory_gb REAL,
		cpu_model TEXT,
		cpu_count INTEGER,
		disk_info TEXT,
		network_info TEXT,
		last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS host_interfaces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL,
		mac TEXT UNIQUE NOT NULL,
		name TEXT DEFAULT 'a',
		hostname TEXT,
		use BOOLEAN DEFAULT 1,
		created DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);
	CREATE INDEX IF NOT EXISTS idx_boot_logs_mac ON boot_logs(mac);
	CREATE INDEX IF NOT EXISTS idx_boot_logs_timestamp ON boot_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_workflows_mac ON workflows(mac);
	CREATE INDEX IF NOT EXISTS idx_workflows_state ON workflows(state);
	CREATE INDEX IF NOT EXISTS idx_asset_data_mac ON asset_data(mac);
	CREATE INDEX IF NOT EXISTS idx_host_interfaces_mac ON host_interfaces(mac);
	CREATE INDEX IF NOT EXISTS idx_host_interfaces_host_id ON host_interfaces(host_id);
	`

	_, err = db.Exec(schema)
	if err != nil {
		return err
	}

	// Add columns to existing tables (for upgrades)
	alterStatements := []string{
		"ALTER TABLE images ADD COLUMN erase_boot_drive BOOLEAN DEFAULT 0",
		"ALTER TABLE images ADD COLUMN erase_all_drives BOOLEAN DEFAULT 0",
		"ALTER TABLE images ADD COLUMN boot_local_after BOOLEAN DEFAULT 0",
		"ALTER TABLE hosts ADD COLUMN ipmi_ip TEXT",
		"ALTER TABLE hosts ADD COLUMN ipmi_username TEXT DEFAULT 'ADMIN'",
		"ALTER TABLE hosts ADD COLUMN ipmi_password TEXT DEFAULT 'ADMIN'",
		"ALTER TABLE hosts ADD COLUMN console_id TEXT",
		"ALTER TABLE hosts ADD COLUMN virtual_media_url TEXT",
	}
	for _, stmt := range alterStatements {
		db.Exec(stmt) // Ignore errors (column may already exist)
	}

	// Insert default images if not exist
	defaultImages := []Image{
		{Name: "baremetalservices", Kernel: "vmlinuz", Initrd: "initramfs", Append: "quiet console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8 ip=dhcp iomem=relaxed", Type: "linux"},
		{Name: "localboot", Kernel: "", Initrd: "", Append: "", Type: "local"},
		{Name: "fedora43", Kernel: "fedora-vmlinuz", Initrd: "fedora-initrd.img", Append: "inst.stage2=https://download.fedoraproject.org/pub/fedora/linux/releases/43/Server/x86_64/os/ inst.ks=http://192.168.10.200/files/fedora-ks.cfg ip=dhcp console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8", Type: "linux"},
		{Name: "fedora43-builder", Kernel: "fedora-vmlinuz", Initrd: "fedora-initrd.img", Append: "inst.stage2=https://download.fedoraproject.org/pub/fedora/linux/releases/43/Server/x86_64/os/ inst.ks=http://192.168.10.200/files/fedora-builder-ks.cfg ip=dhcp console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8", Type: "linux"},
		{Name: "coreos-builder", Kernel: "coreos-kernel", Initrd: "coreos-initramfs", Append: "ignition.config.url=http://192.168.10.200/files/live-builder.ign ignition.firstboot ignition.platform.id=metal coreos.live.rootfs_url=http://192.168.10.200/files/coreos-rootfs.img ip=dhcp console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8", Type: "linux"},
		{Name: "stormbase", Kernel: "memdisk", Initrd: "stormbase.iso", Append: "iso raw", Type: "memdisk"},
	}

	for _, img := range defaultImages {
		_, err = db.Exec(`INSERT OR IGNORE INTO images (name, kernel, initrd, append, type) VALUES (?, ?, ?, ?, ?)`,
			img.Name, img.Kernel, img.Initrd, img.Append, img.Type)
		if err != nil {
			log.Printf("Warning: failed to insert default image %s: %v", img.Name, err)
		}
	}

	// Update fedora43 append line to include inst.stage2 (fix for missing stage2 error)
	db.Exec(`UPDATE images SET append = ? WHERE name = 'fedora43' AND append NOT LIKE '%ttyS0%'`,
		"inst.stage2=https://download.fedoraproject.org/pub/fedora/linux/releases/43/Server/x86_64/os/ inst.ks=http://192.168.10.200/files/fedora-ks.cfg ip=dhcp console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8")

	// Ensure boot_local_after is set on installer images (they reboot after install)
	db.Exec(`UPDATE images SET boot_local_after = 1 WHERE (name LIKE 'fedora%' OR name LIKE 'coreos%') AND boot_local_after = 0`)

	return nil
}

func getImages() ([]Image, error) {
	rows, err := db.Query(`SELECT id, name, kernel, initrd, append, type, erase_boot_drive, erase_all_drives, boot_local_after, created FROM images ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var images []Image
	for rows.Next() {
		var img Image
		var initrd, appendStr sql.NullString
		if err := rows.Scan(&img.ID, &img.Name, &img.Kernel, &initrd, &appendStr, &img.Type, &img.EraseBootDrive, &img.EraseAllDrives, &img.BootLocalAfter, &img.Created); err != nil {
			return nil, err
		}
		if initrd.Valid {
			img.Initrd = initrd.String
		}
		if appendStr.Valid {
			img.Append = appendStr.String
		}
		images = append(images, img)
	}
	return images, nil
}

func getHosts() ([]Host, error) {
	rows, err := db.Query(`SELECT id, mac, hostname, current_image, next_image, cycle_images, cycle_index, last_boot, boot_count, ipmi_ip, ipmi_username, ipmi_password, console_id, created FROM hosts ORDER BY hostname, mac`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var hostname, nextImage, cycleImages, lastBoot, ipmiIP, ipmiUsername, ipmiPassword, consoleID sql.NullString
		if err := rows.Scan(&h.ID, &h.MAC, &hostname, &h.CurrentImage, &nextImage, &cycleImages, &h.CycleIndex, &lastBoot, &h.BootCount, &ipmiIP, &ipmiUsername, &ipmiPassword, &consoleID, &h.Created); err != nil {
			return nil, err
		}
		if hostname.Valid {
			h.Hostname = hostname.String
		}
		if nextImage.Valid {
			h.NextImage = &nextImage.String
		}
		if cycleImages.Valid {
			h.CycleImages = &cycleImages.String
		}
		if lastBoot.Valid {
			h.LastBoot = &lastBoot.String
		}
		if ipmiIP.Valid {
			h.IPMIIP = &ipmiIP.String
		}
		if ipmiUsername.Valid {
			h.IPMIUsername = ipmiUsername.String
		} else {
			h.IPMIUsername = "ADMIN"
		}
		if ipmiPassword.Valid {
			h.IPMIPassword = ipmiPassword.String
		} else {
			h.IPMIPassword = "ADMIN"
		}
		if consoleID.Valid {
			h.ConsoleID = &consoleID.String
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

func getBootLogs(limit int) ([]BootLog, error) {
	rows, err := db.Query(`SELECT id, mac, hostname, image, timestamp FROM boot_logs ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []BootLog
	for rows.Next() {
		var l BootLog
		var hostname sql.NullString
		if err := rows.Scan(&l.ID, &l.MAC, &hostname, &l.Image, &l.Timestamp); err != nil {
			return nil, err
		}
		if hostname.Valid {
			l.Hostname = hostname.String
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func normalizeMAC(mac string) string {
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	return mac
}

func getHostInterfaces(hostID int) ([]HostInterface, error) {
	rows, err := db.Query(`SELECT id, host_id, mac, name, hostname, use, created FROM host_interfaces WHERE host_id = ? ORDER BY name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var interfaces []HostInterface
	for rows.Next() {
		var i HostInterface
		var hostname sql.NullString
		if err := rows.Scan(&i.ID, &i.HostID, &i.MAC, &i.Name, &hostname, &i.Use, &i.Created); err != nil {
			return nil, err
		}
		if hostname.Valid {
			i.Hostname = hostname.String
		}
		interfaces = append(interfaces, i)
	}
	return interfaces, nil
}

func getInterfaceByMAC(mac string) (*HostInterface, error) {
	var i HostInterface
	var hostname sql.NullString
	err := db.QueryRow(`SELECT id, host_id, mac, name, hostname, use, created FROM host_interfaces WHERE mac = ?`, mac).
		Scan(&i.ID, &i.HostID, &i.MAC, &i.Name, &hostname, &i.Use, &i.Created)
	if err != nil {
		return nil, err
	}
	if hostname.Valid {
		i.Hostname = hostname.String
	}
	return &i, nil
}

func getHostByID(id int) (*Host, error) {
	var h Host
	var hostname, nextImage, cycleImages, lastBoot, ipmiIP, ipmiUsername, ipmiPassword, consoleID sql.NullString
	err := db.QueryRow(`SELECT id, mac, hostname, current_image, next_image, cycle_images, cycle_index, last_boot, boot_count, ipmi_ip, ipmi_username, ipmi_password, console_id, created FROM hosts WHERE id = ?`, id).
		Scan(&h.ID, &h.MAC, &hostname, &h.CurrentImage, &nextImage, &cycleImages, &h.CycleIndex, &lastBoot, &h.BootCount, &ipmiIP, &ipmiUsername, &ipmiPassword, &consoleID, &h.Created)
	if err != nil {
		return nil, err
	}
	if hostname.Valid {
		h.Hostname = hostname.String
	}
	if nextImage.Valid {
		h.NextImage = &nextImage.String
	}
	if cycleImages.Valid {
		h.CycleImages = &cycleImages.String
	}
	if lastBoot.Valid {
		h.LastBoot = &lastBoot.String
	}
	if ipmiIP.Valid {
		h.IPMIIP = &ipmiIP.String
	}
	if ipmiUsername.Valid {
		h.IPMIUsername = ipmiUsername.String
	} else {
		h.IPMIUsername = "ADMIN"
	}
	if ipmiPassword.Valid {
		h.IPMIPassword = ipmiPassword.String
	} else {
		h.IPMIPassword = "ADMIN"
	}
	if consoleID.Valid {
		h.ConsoleID = &consoleID.String
	}
	return &h, nil
}

func getAssetData(mac string) (*AssetData, error) {
	var a AssetData
	var manufacturer, productName, serialNumber, biosVersion, cpuModel, diskInfo, networkInfo sql.NullString
	var totalMemoryGB sql.NullFloat64
	var cpuCount sql.NullInt64
	err := db.QueryRow(`SELECT id, mac, manufacturer, product_name, serial_number, bios_version, total_memory_gb, cpu_model, cpu_count, disk_info, network_info, last_updated FROM asset_data WHERE mac = ?`, mac).
		Scan(&a.ID, &a.MAC, &manufacturer, &productName, &serialNumber, &biosVersion, &totalMemoryGB, &cpuModel, &cpuCount, &diskInfo, &networkInfo, &a.LastUpdated)
	if err != nil {
		return nil, err
	}
	if manufacturer.Valid {
		a.Manufacturer = manufacturer.String
	}
	if productName.Valid {
		a.ProductName = productName.String
	}
	if serialNumber.Valid {
		a.SerialNumber = serialNumber.String
	}
	if biosVersion.Valid {
		a.BIOSVersion = biosVersion.String
	}
	if totalMemoryGB.Valid {
		a.TotalMemoryGB = totalMemoryGB.Float64
	}
	if cpuModel.Valid {
		a.CPUModel = cpuModel.String
	}
	if cpuCount.Valid {
		a.CPUCount = int(cpuCount.Int64)
	}
	if diskInfo.Valid {
		a.DiskInfo = diskInfo.String
	}
	if networkInfo.Valid {
		a.NetworkInfo = networkInfo.String
	}
	return &a, nil
}

// Activity logging
func logActivity(level, category string, host *Host, message string) {
	mac := ""
	hostname := ""
	if host != nil {
		mac = host.MAC
		hostname = host.Hostname
	}
	_, err := db.Exec(`INSERT INTO activity_logs (level, category, mac, hostname, message) VALUES (?, ?, ?, ?, ?)`,
		level, category, mac, hostname, message)
	if err != nil {
		log.Printf("Failed to log activity: %v", err)
	}
	log.Printf("[%s] %s: %s (host=%s mac=%s)", level, category, message, hostname, mac)

	// Push SSE events based on category
	sseBroadcast("activityUpdated")
	switch category {
	case "bmh-sync", "boot", "workflow", "image", "config":
		sseBroadcast("hostsUpdated")
	case "ipmi":
		sseBroadcast("hostsUpdated")
	}
}

func getActivityLogs(limit int) ([]ActivityLog, error) {
	rows, err := db.Query(`SELECT id, timestamp, level, category, mac, hostname, message FROM activity_logs ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []ActivityLog
	for rows.Next() {
		var l ActivityLog
		var mac, hostname sql.NullString
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.Level, &l.Category, &mac, &hostname, &l.Message); err != nil {
			return nil, err
		}
		if mac.Valid {
			l.MAC = mac.String
		}
		if hostname.Valid {
			l.Hostname = hostname.String
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// clearDellSessions clears stale Redfish/IPMI sessions on Dell iDRAC.
// Non-Dell BMCs will simply not respond on the Redfish endpoint and we skip silently.
func clearDellSessions(host *Host) {
	if host.IPMIIP == nil || *host.IPMIIP == "" {
		return
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	sessURL := fmt.Sprintf("https://%s/redfish/v1/SessionService/Sessions", *host.IPMIIP)
	req, err := http.NewRequest("GET", sessURL, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth(host.IPMIUsername, host.IPMIPassword)

	resp, err := client.Do(req)
	if err != nil {
		return // Not Dell or Redfish not available
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	var result struct {
		Members []struct {
			ID string `json:"@odata.id"`
		} `json:"Members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	cleared := 0
	for _, m := range result.Members {
		delURL := fmt.Sprintf("https://%s%s", *host.IPMIIP, m.ID)
		delReq, err := http.NewRequest("DELETE", delURL, nil)
		if err != nil {
			continue
		}
		delReq.SetBasicAuth(host.IPMIUsername, host.IPMIPassword)
		delResp, err := client.Do(delReq)
		if err == nil {
			delResp.Body.Close()
			cleared++
		}
	}
	if cleared > 0 {
		log.Printf("Dell iDRAC: cleared %d stale sessions on %s", cleared, *host.IPMIIP)
	}
}

// IPMI functions using pure Go library (no external ipmitool needed)
func getIPMIClient(host *Host) (*ipmi.Client, error) {
	if host.IPMIIP == nil || *host.IPMIIP == "" {
		return nil, fmt.Errorf("no IPMI IP configured for host %s", host.Hostname)
	}

	client, err := ipmi.NewClient(*host.IPMIIP, 623, host.IPMIUsername, host.IPMIPassword)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}

	return client, nil
}

func ipmiPowerStatus(host *Host) (string, error) {
	client, err := getIPMIClient(host)
	if err != nil {
		return "unknown", err
	}
	defer client.Close(context.Background())

	res, err := client.GetChassisStatus(context.Background())
	if err != nil {
		return "unknown", err
	}

	if res.PowerIsOn {
		return "on", nil
	}
	return "off", nil
}

func ipmiPowerOn(host *Host) error {
	client, err := getIPMIClient(host)
	if err != nil {
		return err
	}
	defer client.Close(context.Background())

	// Set boot device based on effective image
	imageName := host.CurrentImage
	if host.NextImage != nil && *host.NextImage != "" {
		imageName = *host.NextImage
	}
	// Check BMH image as source of truth
	if bmhImage := getHostBMHImage(host.Hostname); bmhImage != "" {
		imageName = bmhImage
	}
	bootMsg := fmt.Sprintf("PXE boot → %s", imageName)
	if imageName == "localboot" {
		client.SetBootDevice(context.Background(), ipmi.BootDeviceSelectorForceHardDrive, ipmi.BIOSBootTypeLegacy, false)
		bootMsg = "local boot"
	} else if imageName == "" {
		client.SetBootDevice(context.Background(), ipmi.BootDeviceSelectorForcePXE, ipmi.BIOSBootTypeLegacy, false)
		bootMsg = "PXE boot"
	} else {
		client.SetBootDevice(context.Background(), ipmi.BootDeviceSelectorForcePXE, ipmi.BIOSBootTypeLegacy, false)
	}

	_, err = client.ChassisControl(context.Background(), ipmi.ChassisControlPowerUp)
	if err == nil {
		logActivity("info", "ipmi", host, fmt.Sprintf("Power on command sent (%s)", bootMsg))
		// Reconnect SOL session after power on
		if host.Hostname != "" {
			go func() {
				time.Sleep(15 * time.Second)
				if err := reconnectConsole(host.Hostname); err != nil {
					logActivity("warn", "console", host, fmt.Sprintf("Failed to reconnect console: %v", err))
				}
			}()
		}
	}
	return err
}

func ipmiPowerOff(host *Host) error {
	client, err := getIPMIClient(host)
	if err != nil {
		return err
	}
	defer client.Close(context.Background())

	_, err = client.ChassisControl(context.Background(), ipmi.ChassisControlPowerDown)
	if err == nil {
		logActivity("info", "ipmi", host, "Power off command sent")
		// No log rotation on power off — next power on or PXE boot will rotate
	}
	return err
}

func ipmiRestart(host *Host) error {
	client, err := getIPMIClient(host)
	if err != nil {
		return err
	}
	defer client.Close(context.Background())

	// Set boot device based on effective image
	imageName := host.CurrentImage
	if host.NextImage != nil && *host.NextImage != "" {
		imageName = *host.NextImage
	}
	// Check BMH image as source of truth
	if bmhImage := getHostBMHImage(host.Hostname); bmhImage != "" {
		imageName = bmhImage
	}
	bootMsg := fmt.Sprintf("PXE boot → %s", imageName)
	if imageName == "localboot" {
		client.SetBootDevice(context.Background(), ipmi.BootDeviceSelectorForceHardDrive, ipmi.BIOSBootTypeLegacy, false)
		bootMsg = "local boot"
	} else if imageName == "" {
		client.SetBootDevice(context.Background(), ipmi.BootDeviceSelectorForcePXE, ipmi.BIOSBootTypeLegacy, false)
		bootMsg = "PXE boot"
	} else {
		client.SetBootDevice(context.Background(), ipmi.BootDeviceSelectorForcePXE, ipmi.BIOSBootTypeLegacy, false)
	}

	// Check power state — PowerCycle fails if server is off (IPMI 0xd5)
	statusResp, err := client.GetChassisStatus(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get chassis status: %w", err)
	}

	if statusResp.PowerIsOn {
		_, err = client.ChassisControl(context.Background(), ipmi.ChassisControlPowerCycle)
		if err == nil {
			logActivity("info", "ipmi", host, fmt.Sprintf("Power cycle command sent (%s)", bootMsg))
		}
	} else {
		_, err = client.ChassisControl(context.Background(), ipmi.ChassisControlPowerUp)
		if err == nil {
			logActivity("info", "ipmi", host, fmt.Sprintf("Power on command sent (%s)", bootMsg))
		}
	}
	if err != nil {
		return err
	}

	// Reconnect SOL session after power change
	if host.Hostname != "" {
		go func() {
			time.Sleep(15 * time.Second)
			if err := reconnectConsole(host.Hostname); err != nil {
				logActivity("warn", "console", host, fmt.Sprintf("Failed to reconnect console: %v", err))
			}
		}()
	}
	return nil
}

func ipmiSetBootPXE(host *Host) error {
	client, err := getIPMIClient(host)
	if err != nil {
		return err
	}
	defer client.Close(context.Background())

	err = client.SetBootDevice(context.Background(), ipmi.BootDeviceSelectorForcePXE, ipmi.BIOSBootTypeLegacy, false)
	if err == nil {
		logActivity("info", "ipmi", host, "Set boot device to PXE")
	}
	return err
}

func ipmiSetBootDisk(host *Host) error {
	client, err := getIPMIClient(host)
	if err != nil {
		return err
	}
	defer client.Close(context.Background())

	err = client.SetBootDevice(context.Background(), ipmi.BootDeviceSelectorForceHardDrive, ipmi.BIOSBootTypeLegacy, false)
	if err == nil {
		logActivity("info", "ipmi", host, "Set boot device to disk")
	}
	return err
}

// startPowerTransition sends an IPMI power command and spawns a background
// goroutine to verify the state actually changed, retrying up to 3 times.
func startPowerTransition(host *Host, action string) error {
	desiredOn := action != "power_off"

	// Cancel any existing transition for this host
	powerTransitions.Delete(host.Hostname)

	// Rotate console logs before IPMI command so ipmiserial starts a new log
	imageName := getHostBMHImage(host.Hostname)
	if imageName == "" {
		imageName = host.CurrentImage
	}
	if imageName == "" || imageName == "localboot" {
		imageName = "idle"
	}
	label := fmt.Sprintf("%s-%s", imageName, time.Now().Format("20060102-150405"))
	if err := rotateConsoleLogs(host.Hostname, label); err != nil {
		log.Printf("Failed to rotate console logs for %s before %s: %v", host.Hostname, action, err)
	}

	// Send the initial IPMI command synchronously (catches auth/network errors)
	var sendErr error
	switch action {
	case "power_on":
		sendErr = ipmiPowerOn(host)
	case "power_off":
		sendErr = ipmiPowerOff(host)
	case "restart":
		sendErr = ipmiRestart(host)
	}
	if sendErr != nil {
		return sendErr
	}

	t := &PowerTransition{
		Hostname:    host.Hostname,
		Action:      action,
		DesiredOn:   desiredOn,
		StartedAt:   time.Now(),
		Attempt:     1,
		MaxAttempts: 3,
	}
	powerTransitions.Store(host.Hostname, t)

	go verifyPowerTransition(host.Hostname, t)

	return nil
}

func verifyPowerTransition(hostname string, t *PowerTransition) {
	const (
		initialDelay  = 5 * time.Second
		pollInterval  = 3 * time.Second
		maxWaitPerTry = 30 * time.Second
		totalTimeout  = 120 * time.Second
	)

	deadline := time.Now().Add(totalTimeout)
	time.Sleep(initialDelay)

	for {
		// Check if this transition was superseded
		val, ok := powerTransitions.Load(hostname)
		if !ok || val.(*PowerTransition) != t {
			return
		}

		if time.Now().After(deadline) {
			t.mu.Lock()
			t.Done = true
			t.Failed = true
			t.mu.Unlock()
			logTransitionResult(hostname, t, "timed out")
			go cleanupTransition(hostname, 30*time.Second)
			return
		}

		host, err := getHostByHostname(hostname)
		if err != nil {
			t.mu.Lock()
			t.Done = true
			t.Failed = true
			t.mu.Unlock()
			go cleanupTransition(hostname, 30*time.Second)
			return
		}

		status, err := ipmiPowerStatus(host)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		// Update cache on every poll so UI reflects real-time state
		powerStateCache.Store(hostname, status)
		sseBroadcast("hostsUpdated")

		isDesired := (t.DesiredOn && status == "on") || (!t.DesiredOn && status == "off")
		// For restart, don't count "on" as success too early (might not have cycled yet)
		if t.Action == "restart" && status == "on" && time.Since(t.StartedAt) < 10*time.Second {
			isDesired = false
		}

		if isDesired {
			t.mu.Lock()
			t.Done = true
			t.Failed = false
			t.mu.Unlock()
			logTransitionResult(hostname, t, "confirmed")
			go updateBMHPowerStatus(hostname, t.DesiredOn)
			go cleanupTransition(hostname, 5*time.Second)
			return
		}

		// Check if this attempt has waited long enough
		attemptStart := t.StartedAt.Add(time.Duration(t.Attempt-1) * maxWaitPerTry)
		if time.Since(attemptStart) > maxWaitPerTry {
			t.mu.Lock()
			if t.Attempt >= t.MaxAttempts {
				t.Done = true
				t.Failed = true
				t.mu.Unlock()
				logTransitionResult(hostname, t, "failed after 3 attempts")
				go cleanupTransition(hostname, 30*time.Second)
				return
			}
			t.Attempt++
			attempt := t.Attempt
			t.mu.Unlock()

			logActivity("warn", "ipmi", host, fmt.Sprintf(
				"Power %s not confirmed, retrying (attempt %d/3)", t.Action, attempt))

			switch t.Action {
			case "power_on":
				ipmiPowerOn(host)
			case "power_off":
				ipmiPowerOff(host)
			case "restart":
				ipmiRestart(host)
			}

			time.Sleep(initialDelay)
			continue
		}

		time.Sleep(pollInterval)
	}
}

func logTransitionResult(hostname string, t *PowerTransition, result string) {
	host, err := getHostByHostname(hostname)
	if err != nil {
		log.Printf("IPMI transition %s for %s: %s (attempt %d)", t.Action, hostname, result, t.Attempt)
		return
	}
	level := "info"
	if t.Failed {
		level = "error"
	}
	logActivity(level, "ipmi", host, fmt.Sprintf(
		"Power %s %s (attempt %d/%d, took %s)",
		t.Action, result, t.Attempt, t.MaxAttempts, time.Since(t.StartedAt).Round(time.Second)))
}

func cleanupTransition(hostname string, delay time.Duration) {
	time.Sleep(delay)
	powerTransitions.Delete(hostname)
}

func getTransitionState(hostname string) string {
	val, ok := powerTransitions.Load(hostname)
	if !ok {
		return ""
	}
	t := val.(*PowerTransition)
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Done && t.Failed {
		return "failed"
	}
	if t.Done {
		return ""
	}

	switch t.Action {
	case "power_on":
		return "powering_on"
	case "power_off":
		return "powering_off"
	case "restart":
		return "restarting"
	}
	return ""
}

func transitionLabel(state string) string {
	switch state {
	case "powering_on":
		return `<span class="spinner"></span> Powering On`
	case "powering_off":
		return `<span class="spinner"></span> Powering Off`
	case "restarting":
		return `<span class="spinner"></span> Restarting`
	case "failed":
		return `! Failed`
	}
	return state
}

func transitionCSSClass(state string) string {
	switch state {
	case "powering_on", "powering_off", "restarting":
		return "power-transitioning"
	case "failed":
		return "power-failed"
	}
	return "power-unknown"
}

// Console server integration
func rotateConsoleLogs(hostname, label string) error {
	reqURL := fmt.Sprintf("%s/api/servers/%s/logs/rotate?name=%s",
		ConsoleServerURL, hostname, url.QueryEscape(label))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(reqURL, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("console server returned status %d", resp.StatusCode)
	}
	return nil
}

// reconnectConsole tells ipmiserial to drop and re-establish the SOL session.
// Called after power on/cycle since the BMC resets SOL on chassis events.
func reconnectConsole(hostname string) error {
	reqURL := fmt.Sprintf("%s/api/servers/%s/reconnect", ConsoleServerURL, hostname)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(reqURL, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("console server returned status %d", resp.StatusCode)
	}
	return nil
}

// Workflow engine
var workflowMutex sync.Mutex

func getActiveWorkflows() ([]Workflow, error) {
	rows, err := db.Query(`SELECT id, mac, type, state, target_image, erase_boot_drive, erase_all_drives, started, updated, error_message
		FROM workflows WHERE state NOT IN ('completed', 'failed') ORDER BY started`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workflows []Workflow
	for rows.Next() {
		var w Workflow
		var errMsg sql.NullString
		if err := rows.Scan(&w.ID, &w.MAC, &w.Type, &w.State, &w.TargetImage, &w.EraseBootDrive, &w.EraseAllDrives, &w.Started, &w.Updated, &errMsg); err != nil {
			return nil, err
		}
		if errMsg.Valid {
			w.ErrorMessage = &errMsg.String
		}
		workflows = append(workflows, w)
	}
	return workflows, nil
}

func updateWorkflowState(id int, state string, errMsg *string) {
	if errMsg != nil {
		db.Exec(`UPDATE workflows SET state = ?, updated = CURRENT_TIMESTAMP, error_message = ? WHERE id = ?`, state, *errMsg, id)
	} else {
		db.Exec(`UPDATE workflows SET state = ?, updated = CURRENT_TIMESTAMP WHERE id = ?`, state, id)
	}
}

func getHostByMAC(mac string) (*Host, error) {
	var h Host
	var hostname, nextImage, cycleImages, lastBoot, ipmiIP, ipmiUsername, ipmiPassword, consoleID sql.NullString
	err := db.QueryRow(`SELECT id, mac, hostname, current_image, next_image, cycle_images, cycle_index, last_boot, boot_count, ipmi_ip, ipmi_username, ipmi_password, console_id, created FROM hosts WHERE mac = ?`, mac).
		Scan(&h.ID, &h.MAC, &hostname, &h.CurrentImage, &nextImage, &cycleImages, &h.CycleIndex, &lastBoot, &h.BootCount, &ipmiIP, &ipmiUsername, &ipmiPassword, &consoleID, &h.Created)
	if err != nil {
		return nil, err
	}
	if hostname.Valid {
		h.Hostname = hostname.String
	}
	if nextImage.Valid {
		h.NextImage = &nextImage.String
	}
	if cycleImages.Valid {
		h.CycleImages = &cycleImages.String
	}
	if lastBoot.Valid {
		h.LastBoot = &lastBoot.String
	}
	if ipmiIP.Valid {
		h.IPMIIP = &ipmiIP.String
	}
	if ipmiUsername.Valid {
		h.IPMIUsername = ipmiUsername.String
	} else {
		h.IPMIUsername = "ADMIN"
	}
	if ipmiPassword.Valid {
		h.IPMIPassword = ipmiPassword.String
	} else {
		h.IPMIPassword = "ADMIN"
	}
	if consoleID.Valid {
		h.ConsoleID = &consoleID.String
	}
	return &h, nil
}

func getHostByHostname(hostname string) (*Host, error) {
	var h Host
	var hn, nextImage, cycleImages, lastBoot, ipmiIP, ipmiUsername, ipmiPassword, consoleID sql.NullString
	err := db.QueryRow(`SELECT id, mac, hostname, current_image, next_image, cycle_images, cycle_index, last_boot, boot_count, ipmi_ip, ipmi_username, ipmi_password, console_id, created FROM hosts WHERE hostname = ?`, hostname).
		Scan(&h.ID, &h.MAC, &hn, &h.CurrentImage, &nextImage, &cycleImages, &h.CycleIndex, &lastBoot, &h.BootCount, &ipmiIP, &ipmiUsername, &ipmiPassword, &consoleID, &h.Created)
	if err != nil {
		return nil, err
	}
	if hn.Valid {
		h.Hostname = hn.String
	}
	if nextImage.Valid {
		h.NextImage = &nextImage.String
	}
	if cycleImages.Valid {
		h.CycleImages = &cycleImages.String
	}
	if lastBoot.Valid {
		h.LastBoot = &lastBoot.String
	}
	if ipmiIP.Valid {
		h.IPMIIP = &ipmiIP.String
	}
	if ipmiUsername.Valid {
		h.IPMIUsername = ipmiUsername.String
	} else {
		h.IPMIUsername = "ADMIN"
	}
	if ipmiPassword.Valid {
		h.IPMIPassword = ipmiPassword.String
	} else {
		h.IPMIPassword = "ADMIN"
	}
	if consoleID.Valid {
		h.ConsoleID = &consoleID.String
	}
	return &h, nil
}

func getHostIP(mac string) string {
	// For now, we'll need to get the IP from DHCP leases or DNS
	// This is a placeholder - in production you'd query your DHCP server
	// For now we'll look up via hostname
	host, err := getHostByMAC(mac)
	if err != nil || host.Hostname == "" {
		return ""
	}
	// Try to resolve hostname
	// This assumes the host is reachable by hostname
	return host.Hostname
}

func checkBaremetalReady(hostIP string) bool {
	if hostIP == "" {
		return false
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s:8080/health", hostIP))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func triggerDiskWipe(hostIP string, allDisks bool) error {
	if hostIP == "" {
		return fmt.Errorf("no host IP available")
	}
	url := fmt.Sprintf("http://%s:8080/disks/wipe", hostIP)
	if !allDisks {
		url = fmt.Sprintf("http://%s:8080/disks/wipe/sda", hostIP)
	}
	client := &http.Client{Timeout: 10 * time.Minute} // Disk wipe can take a while
	resp, err := client.Post(url, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("disk wipe returned status %d", resp.StatusCode)
	}
	return nil
}

// Baremetalservices IPMI reset - resets IPMI to DHCP and sets credentials
func baremetalResetIPMI(hostIP, username, password string) error {
	if hostIP == "" {
		return fmt.Errorf("no host IP available")
	}

	url := fmt.Sprintf("http://%s:8080/ipmi/reset", hostIP)

	body := map[string]string{
		"username": username,
		"password": password,
	}
	jsonBody, _ := json.Marshal(body)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("IPMI reset returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// Baremetalservices get MAC addresses - returns all network interface MACs
func baremetalGetMACs(hostIP string) (map[string]string, error) {
	if hostIP == "" {
		return nil, fmt.Errorf("no host IP available")
	}

	url := fmt.Sprintf("http://%s:8080/macs", hostIP)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get MACs returned status %d", resp.StatusCode)
	}

	var result struct {
		Status string            `json:"status"`
		Data   map[string]string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Status != "ok" {
		return nil, fmt.Errorf("get MACs returned status: %s", result.Status)
	}

	return result.Data, nil
}

// API handler for baremetalservices IPMI reset
func handleAPIBaremetalIPMIReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		http.Error(w, "host parameter required", http.StatusBadRequest)
		return
	}

	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	hostIP := host.Hostname // Use hostname for DNS resolution
	if !checkBaremetalReady(hostIP) {
		http.Error(w, "Host not running baremetalservices", http.StatusBadRequest)
		return
	}

	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" {
		username = "ADMIN"
	}
	if password == "" {
		password = "ADMIN"
	}

	if err := baremetalResetIPMI(hostIP, username, password); err != nil {
		logActivity("error", "baremetal", host, fmt.Sprintf("IPMI reset failed: %v", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logActivity("info", "baremetal", host, fmt.Sprintf("IPMI reset to DHCP with username %s", username))

	// Update host's stored IPMI credentials
	db.Exec(`UPDATE hosts SET ipmi_username = ?, ipmi_password = ? WHERE hostname = ?`, username, password, hostname)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "IPMI reset to DHCP"})
}

// API handler for baremetalservices get MACs
func handleAPIBaremetalGetMACs(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		http.Error(w, "host parameter required", http.StatusBadRequest)
		return
	}

	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	hostIP := host.Hostname
	if !checkBaremetalReady(hostIP) {
		http.Error(w, "Host not running baremetalservices", http.StatusBadRequest)
		return
	}

	macs, err := baremetalGetMACs(hostIP)
	if err != nil {
		logActivity("error", "baremetal", host, fmt.Sprintf("Get MACs failed: %v", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logActivity("info", "baremetal", host, fmt.Sprintf("Retrieved %d MAC addresses", len(macs)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(macs)
}

// API handler to auto-discover and register all interfaces from baremetalservices
func handleAPIBaremetalAutoDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		http.Error(w, "host parameter required", http.StatusBadRequest)
		return
	}

	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	hostIP := host.Hostname
	if !checkBaremetalReady(hostIP) {
		http.Error(w, "Host not running baremetalservices", http.StatusBadRequest)
		return
	}

	macs, err := baremetalGetMACs(hostIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Sort interface names for consistent ordering
	var names []string
	for name := range macs {
		if name != "ipmi" { // Skip IPMI interface for PXE
			names = append(names, name)
		}
	}
	sort.Strings(names)

	added := 0
	for i, name := range names {
		mac := strings.ToLower(macs[name])

		// Skip if already registered
		var exists int
		db.QueryRow(`SELECT COUNT(*) FROM host_interfaces WHERE mac = ?`, mac).Scan(&exists)
		if exists > 0 {
			continue
		}

		// Determine interface letter (a, b, c, etc.)
		letter := string('a' + i)
		ifHostname := ""
		if i == 0 {
			ifHostname = fmt.Sprintf("%s.g10.lo", hostname)
		} else {
			ifHostname = fmt.Sprintf("%s%s.g10.lo", hostname, letter)
		}

		// Default: enable primary (a), disable others
		use := i == 0

		_, err := db.Exec(`INSERT INTO host_interfaces (host_id, mac, name, hostname, use) VALUES (?, ?, ?, ?, ?)`,
			host.ID, mac, name, ifHostname, use)
		if err == nil {
			added++
			logActivity("info", "baremetal", host, fmt.Sprintf("Auto-discovered interface %s: %s (%s)", letter, mac, name))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"discovered": len(names),
		"added":      added,
	})
}

func createEraseWorkflow(mac, targetImage string, eraseBootDrive, eraseAllDrives bool) error {
	// Cancel any existing workflow for this host
	db.Exec(`UPDATE workflows SET state = 'cancelled' WHERE mac = ? AND state NOT IN ('completed', 'failed', 'cancelled')`, mac)

	_, err := db.Exec(`INSERT INTO workflows (mac, type, state, target_image, erase_boot_drive, erase_all_drives) VALUES (?, 'erase', 'pending', ?, ?, ?)`,
		mac, targetImage, eraseBootDrive, eraseAllDrives)
	if err != nil {
		return err
	}

	host, _ := getHostByMAC(mac)
	logActivity("info", "workflow", host, fmt.Sprintf("Created erase workflow for target image %s", targetImage))

	// Set host to boot baremetalservices for the erase operation
	db.Exec(`UPDATE hosts SET next_image = 'baremetalservices' WHERE mac = ?`, mac)

	return nil
}

func processActiveWorkflows() {
	workflowMutex.Lock()
	defer workflowMutex.Unlock()

	workflows, err := getActiveWorkflows()
	if err != nil {
		log.Printf("Failed to get active workflows: %v", err)
		return
	}

	for _, w := range workflows {
		host, err := getHostByMAC(w.MAC)
		if err != nil {
			errMsg := fmt.Sprintf("Host not found: %v", err)
			updateWorkflowState(w.ID, "failed", &errMsg)
			continue
		}

		hostIP := getHostIP(w.MAC)

		switch w.State {
		case "pending":
			// Waiting for host to boot into baremetalservices
			if checkBaremetalReady(hostIP) {
				logActivity("info", "workflow", host, "Host ready, starting disk wipe")
				updateWorkflowState(w.ID, "erasing", nil)
				go func(wf Workflow, hip string, h *Host) {
					err := triggerDiskWipe(hip, wf.EraseAllDrives)
					if err != nil {
						errMsg := fmt.Sprintf("Disk wipe failed: %v", err)
						logActivity("error", "workflow", h, errMsg)
						updateWorkflowState(wf.ID, "failed", &errMsg)
					} else {
						logActivity("info", "workflow", h, "Disk wipe completed")
						updateWorkflowState(wf.ID, "waiting", nil)
					}
				}(w, hostIP, host)
			}

		case "waiting":
			// Disk wipe done, set next boot to target image and reboot
			db.Exec(`UPDATE hosts SET next_image = ? WHERE mac = ?`, w.TargetImage, w.MAC)
			logActivity("info", "workflow", host, fmt.Sprintf("Setting next boot to %s", w.TargetImage))

			// If IPMI available, trigger reboot
			if host.IPMIIP != nil && *host.IPMIIP != "" {
				if err := ipmiRestart(host); err != nil {
					logActivity("warn", "workflow", host, fmt.Sprintf("IPMI restart failed: %v", err))
				}
			}
			updateWorkflowState(w.ID, "booting", nil)

		case "booting":
			// Check if the host has booted the target image
			if host.CurrentImage == w.TargetImage || (host.LastBoot != nil && host.CurrentImage != "baremetalservices") {
				logActivity("info", "workflow", host, "Workflow completed successfully")
				updateWorkflowState(w.ID, "completed", nil)
			}
		}
	}
}

func workflowProcessor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		processActiveWorkflows()
	}
}

// Boot script that chains to dynamic iPXE endpoint
func handleBootIPXE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, `#!ipxe
dhcp
chain http://192.168.10.200/ipxe?mac=${net0/mac} || shell
`)
}

// iPXE boot script handler
func handleIPXE(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC address required", http.StatusBadRequest)
		return
	}

	var host Host

	// First check if this MAC is a known interface
	iface, err := getInterfaceByMAC(mac)
	if err == nil {
		// Found in interfaces table
		if !iface.Use {
			// Interface disabled - boot local
			log.Printf("iPXE: MAC %s interface disabled, booting local", mac)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "#!ipxe\nexit\n")
			return
		}
		// Interface enabled - get the host by ID
		hostPtr, err := getHostByID(iface.HostID)
		if err != nil {
			log.Printf("Host ID %d not found for interface %s: %v", iface.HostID, mac, err)
			http.Error(w, "Host not found", http.StatusInternalServerError)
			return
		}
		host = *hostPtr
		// Update boot stats
		db.Exec(`UPDATE hosts SET last_boot = CURRENT_TIMESTAMP, boot_count = boot_count + 1 WHERE id = ?`, iface.HostID)
	} else {
		// Not in interfaces table - check hosts table directly
		var hostnameNull, nextImage, cycleImages, lastBoot sql.NullString
		err = db.QueryRow(`SELECT id, mac, hostname, current_image, next_image, cycle_images, cycle_index, last_boot, boot_count FROM hosts WHERE mac = ?`, mac).
			Scan(&host.ID, &host.MAC, &hostnameNull, &host.CurrentImage, &nextImage, &cycleImages, &host.CycleIndex, &lastBoot, &host.BootCount)

		if err == sql.ErrNoRows {
			// Auto-register new host
			result, err := db.Exec(`INSERT INTO hosts (mac, current_image) VALUES (?, 'baremetalservices')`, mac)
			if err != nil {
				log.Printf("Failed to auto-register host %s: %v", mac, err)
			} else {
				// Also create primary interface entry
				hostID, _ := result.LastInsertId()
				host.ID = int(hostID)
				db.Exec(`INSERT INTO host_interfaces (host_id, mac, name, hostname, use) VALUES (?, ?, 'a', '', 1)`, hostID, mac)
			}
			host.MAC = mac
			host.CurrentImage = "baremetalservices"
			logActivity("info", "boot", nil, fmt.Sprintf("New host discovered: %s", mac))
		} else if err != nil {
			log.Printf("Database error for MAC %s: %v", mac, err)
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		} else {
			if hostnameNull.Valid {
				host.Hostname = hostnameNull.String
			}
			if nextImage.Valid {
				host.NextImage = &nextImage.String
			}
			if cycleImages.Valid {
				host.CycleImages = &cycleImages.String
			}
			if lastBoot.Valid {
				host.LastBoot = &lastBoot.String
			}
		}
	}

	// Get full host info for IPMI operations
	fullHost, _ := getHostByID(host.ID)

	// Determine boot image from BMH CRD (source of truth is mkube, not SQLite)
	imageName := ""
	if host.Hostname != "" {
		if val, ok := bmhMap.Load(host.Hostname); ok {
			bmh := val.(bmhObject)
			imageName = bmh.Spec.Image
		}
	}
	if imageName == "" {
		imageName = host.CurrentImage // fallback to SQLite for unsynced hosts
	}
	if imageName == "" {
		imageName = "localboot"
	}

	// localboot = boot from disk
	if imageName == "localboot" {
		log.Printf("iPXE boot: MAC=%s hostname=%s image=localboot (exit)", mac, host.Hostname)
		db.Exec(`UPDATE hosts SET last_boot = CURRENT_TIMESTAMP, boot_count = boot_count + 1 WHERE id = ?`, host.ID)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "#!ipxe\nexit\n")
		return
	}

	// Look up iSCSI CDROM by name
	var cdrom iscsiCdromObject
	var cdromFound bool
	if val, ok := iscsiCdromMap.Load(imageName); ok {
		cdrom = val.(iscsiCdromObject)
		cdromFound = true
	}

	if !cdromFound || cdrom.Status.TargetIQN == "" {
		log.Printf("iPXE boot: MAC=%s hostname=%s image=%s — iSCSI CDROM not found or no IQN, booting local", mac, host.Hostname, imageName)
		logActivity("warn", "boot", fullHost, fmt.Sprintf("iSCSI CDROM %q not found, booting local", imageName))
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "#!ipxe\nexit\n")
		return
	}

	// NOTE: boot_local_after is NOT done here — the iPXE script is served before the ISO
	// even boots. The installer (coreos-installer ignition) should switch the BMH to localboot
	// after install completes, either via a REST call or by a post-install hook.

	// Rotate console logs when booting a new image
	if fullHost != nil && fullHost.Hostname != "" {
		go func() {
			label := fmt.Sprintf("%s-%s", imageName, time.Now().Format("20060102-150405"))
			if err := rotateConsoleLogs(fullHost.Hostname, label); err != nil {
				log.Printf("Failed to rotate console logs for %s: %v", fullHost.Hostname, err)
			} else {
				logActivity("info", "console", fullHost, fmt.Sprintf("Rotated console logs with label %s", label))
			}
		}()
	}

	// Update boot stats
	db.Exec(`UPDATE hosts SET last_boot = CURRENT_TIMESTAMP, boot_count = boot_count + 1 WHERE id = ?`, host.ID)
	db.Exec(`INSERT INTO boot_logs (mac, hostname, image) VALUES (?, ?, ?)`, host.MAC, host.Hostname, imageName)
	logActivity("info", "boot", fullHost, fmt.Sprintf("Booting iSCSI %s (iqn=%s)", imageName, cdrom.Status.TargetIQN))
	log.Printf("iPXE boot: MAC=%s hostname=%s image=%s iqn=%s", mac, host.Hostname, imageName, cdrom.Status.TargetIQN)

	// Generate iPXE sanboot script
	w.Header().Set("Content-Type", "text/plain")
	script := "#!ipxe\n"
	script += fmt.Sprintf("echo Booting %s for %s (%s)\n", imageName, host.Hostname, mac)
	script += fmt.Sprintf("sanboot iscsi:%s::::%s\n", ISCSIPortalIP, cdrom.Status.TargetIQN)
	fmt.Fprint(w, script)
}

// API handlers
func handleAPIHosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		hosts, err := getHosts()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(hosts)

	case "POST":
		var h Host
		if err := json.NewDecoder(r.Body).Decode(&h); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.MAC = normalizeMAC(h.MAC)
		_, err := db.Exec(`INSERT INTO hosts (mac, hostname, current_image) VALUES (?, ?, ?)
			ON CONFLICT(mac) DO UPDATE SET hostname = ?, current_image = ?`,
			h.MAC, h.Hostname, h.CurrentImage, h.Hostname, h.CurrentImage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(h)
	}
}

func handleAPIHostAction(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
		return
	}

	action := r.URL.Query().Get("action")

	// Look up host to get hostname for BMH operations
	host, hostErr := getHostByMAC(mac)

	switch action {
	case "set_image":
		image := r.FormValue("image")
		if image == "" {
			http.Error(w, "image required", http.StatusBadRequest)
			return
		}

		// PATCH BMH in mkube (source of truth)
		if hostErr == nil && host.Hostname != "" {
			if err := updateBMHImage(host.Hostname, image); err != nil {
				log.Printf("set_image: failed to PATCH BMH for %s: %v", host.Hostname, err)
				logActivity("warn", "boot", host, fmt.Sprintf("Failed to update BMH image: %v", err))
			}
		}
		// Also update SQLite for local state
		db.Exec(`UPDATE hosts SET current_image = ? WHERE mac = ?`, image, mac)

	case "set_config":
		config := r.FormValue("config")
		if hostErr == nil && host.Hostname != "" {
			if err := updateBMHBootConfig(host.Hostname, config); err != nil {
				log.Printf("set_config: failed to PATCH BMH for %s: %v", host.Hostname, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "host not found", http.StatusNotFound)
			return
		}

	case "delete":
		_, err := db.Exec(`DELETE FROM hosts WHERE mac = ?`, mac)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	w.Header().Set("HX-Trigger", "hostsUpdated")
	w.WriteHeader(http.StatusOK)
}

func handleAPIImages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		images, err := getImages()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(images)

	case "POST":
		var img Image
		if err := json.NewDecoder(r.Body).Decode(&img); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`INSERT INTO images (name, kernel, initrd, append, type, erase_boot_drive, erase_all_drives, boot_local_after) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET kernel = ?, initrd = ?, append = ?, type = ?, erase_boot_drive = ?, erase_all_drives = ?, boot_local_after = ?`,
			img.Name, img.Kernel, img.Initrd, img.Append, img.Type, img.EraseBootDrive, img.EraseAllDrives, img.BootLocalAfter,
			img.Kernel, img.Initrd, img.Append, img.Type, img.EraseBootDrive, img.EraseAllDrives, img.BootLocalAfter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("HX-Trigger", "imagesUpdated")
		w.WriteHeader(http.StatusCreated)
	}
}

func handleAPIImageUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	id := r.FormValue("id")
	name := r.FormValue("name")
	kernel := r.FormValue("kernel")
	initrd := r.FormValue("initrd")
	appendStr := r.FormValue("append")
	imgType := r.FormValue("type")
	eraseBootDrive := r.FormValue("erase_boot_drive") == "on"
	eraseAllDrives := r.FormValue("erase_all_drives") == "on"
	bootLocalAfter := r.FormValue("boot_local_after") == "on"

	_, err := db.Exec(`UPDATE images SET name = ?, kernel = ?, initrd = ?, append = ?, type = ?, erase_boot_drive = ?, erase_all_drives = ?, boot_local_after = ? WHERE id = ?`,
		name, kernel, initrd, appendStr, imgType, eraseBootDrive, eraseAllDrives, bootLocalAfter, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Trigger", "imagesUpdated")
	w.WriteHeader(http.StatusOK)
}

func handleAPIImageDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`DELETE FROM images WHERE id = ?`, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Trigger", "imagesUpdated")
	w.WriteHeader(http.StatusOK)
}

func handleAPIImageAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	name := r.FormValue("name")
	kernel := r.FormValue("kernel")
	initrd := r.FormValue("initrd")
	appendStr := r.FormValue("append")
	imgType := r.FormValue("type")
	if imgType == "" {
		imgType = "linux"
	}
	eraseBootDrive := r.FormValue("erase_boot_drive") == "on"
	eraseAllDrives := r.FormValue("erase_all_drives") == "on"
	bootLocalAfter := r.FormValue("boot_local_after") == "on"

	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`INSERT INTO images (name, kernel, initrd, append, type, erase_boot_drive, erase_all_drives, boot_local_after) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		name, kernel, initrd, appendStr, imgType, eraseBootDrive, eraseAllDrives, bootLocalAfter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Trigger", "imagesUpdated")
	w.WriteHeader(http.StatusCreated)
}

// IPMI API handlers
func handleAPIHostIPMI(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		http.Error(w, "host parameter required", http.StatusBadRequest)
		return
	}

	action := r.URL.Query().Get("action")
	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	if host.IPMIIP == nil || *host.IPMIIP == "" {
		http.Error(w, "IPMI not configured for this host", http.StatusBadRequest)
		return
	}

	// Clear stale sessions on Dell iDRAC before operations
	clearDellSessions(host)

	switch action {
	case "restart", "power_on", "power_off":
		if err := startPowerTransition(host, action); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "set_boot":
		device := r.URL.Query().Get("device")
		switch device {
		case "pxe":
			if err := ipmiSetBootPXE(host); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case "disk":
			if err := ipmiSetBootDisk(host); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "device must be 'pxe' or 'disk'", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	// Clear sessions after operation to avoid accumulation
	go clearDellSessions(host)

	// Return activity table as out-of-band swap for immediate update
	w.Header().Set("Content-Type", "text/html")
	logs, _ := getActivityLogs(50)
	fmt.Fprint(w, `<div id="activity-table" hx-swap-oob="innerHTML">`)
	templates.ExecuteTemplate(w, "activity_log.html", logs)
	fmt.Fprint(w, `</div>`)
}

func handleAPIHostIPMIStatus(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")
	w.Header().Set("Content-Type", "text/html")

	if hostname == "" {
		fmt.Fprint(w, `<span class="power-badge power-unknown">-</span>`)
		return
	}

	host, err := getHostByHostname(hostname)
	if err != nil || host.IPMIIP == nil || *host.IPMIIP == "" {
		fmt.Fprint(w, `<span class="power-badge power-unknown">-</span>`)
		return
	}

	// Check for active transition first
	transState := getTransitionState(hostname)

	if transState != "" {
		label := transitionLabel(transState)
		cssClass := transitionCSSClass(transState)
		fmt.Fprintf(w,
			`<span class="power-badge %s"><span class="spinner"></span> %s</span>`,
			cssClass, label)
		return
	}

	// Read from cache (populated by ipmiPowerPoller)
	status := "unknown"
	if cached, ok := powerStateCache.Load(hostname); ok {
		status = cached.(string)
	}
	cssClass := "power-unknown"
	label := "-"
	switch status {
	case "on":
		cssClass = "power-on"
		label = "ON"
	case "off":
		cssClass = "power-off"
		label = "OFF"
	}
	fmt.Fprintf(w,
		`<span class="power-badge %s">%s</span>`,
		cssClass, label)
}

func handleAPIHostIPMITest(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		http.Error(w, "host parameter required", http.StatusBadRequest)
		return
	}

	host, err := getHostByHostname(hostname)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<span class="badge badge-error">Not Found</span>`)
		return
	}

	if host.IPMIIP == nil || *host.IPMIIP == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<span class="badge badge-warn">No IPMI</span>`)
		return
	}

	status, err := ipmiPowerStatus(host)
	if err != nil {
		logActivity("error", "ipmi", host, fmt.Sprintf("IPMI test failed: %v", err))
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span class="badge badge-error" title="%s">Failed</span>`, err.Error())
		return
	}

	logActivity("info", "ipmi", host, fmt.Sprintf("IPMI test successful, power status: %s", status))
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<span class="badge badge-info">OK: %s</span>`, status)
}

func handleAPIHostIPMIConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		http.Error(w, "host parameter required", http.StatusBadRequest)
		return
	}

	r.ParseForm()
	ipmiIP := r.FormValue("ipmi_ip")
	ipmiUsername := r.FormValue("ipmi_username")
	ipmiPassword := r.FormValue("ipmi_password")

	if ipmiUsername == "" {
		ipmiUsername = "ADMIN"
	}
	if ipmiPassword == "" {
		ipmiPassword = "ADMIN"
	}

	_, err := db.Exec(`UPDATE hosts SET ipmi_ip = ?, ipmi_username = ?, ipmi_password = ? WHERE hostname = ?`,
		ipmiIP, ipmiUsername, ipmiPassword, hostname)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	host, _ := getHostByHostname(hostname)
	logActivity("info", "config", host, fmt.Sprintf("Updated IPMI configuration (IP: %s)", ipmiIP))

	w.Header().Set("HX-Trigger", "hostsUpdated")
	w.WriteHeader(http.StatusOK)
}

func handleAPIHostConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
		return
	}

	r.ParseForm()
	hostname := r.FormValue("hostname")
	ipmiIP := r.FormValue("ipmi_ip")
	ipmiUsername := r.FormValue("ipmi_username")
	ipmiPassword := r.FormValue("ipmi_password")

	if ipmiUsername == "" {
		ipmiUsername = "ADMIN"
	}
	if ipmiPassword == "" {
		ipmiPassword = "ADMIN"
	}

	_, err := db.Exec(`UPDATE hosts SET hostname = ?, ipmi_ip = ?, ipmi_username = ?, ipmi_password = ? WHERE mac = ?`,
		hostname, ipmiIP, ipmiUsername, ipmiPassword, mac)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	host, _ := getHostByMAC(mac)
	logActivity("info", "config", host, fmt.Sprintf("Updated host configuration (hostname: %s, IPMI IP: %s)", hostname, ipmiIP))

	w.Header().Set("HX-Trigger", "hostsUpdated")
	w.WriteHeader(http.StatusOK)
}

// NetworkHost represents a host from the network manager API
type NetworkHost struct {
	MACAddress string `json:"mac_address"`
	Hostname   string `json:"hostname"`
	DNSName    string `json:"dns_name"`
	IPAddress  string `json:"ip_address"`
}

// lookupHostnameByMAC queries the network manager API for hostname by MAC address
func lookupHostnameByMAC(mac string) string {
	// Query network manager API
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(NetworkManagerURL + "/api/hosts")
	if err != nil {
		log.Printf("Failed to query network manager: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Network manager returned status %d", resp.StatusCode)
		return ""
	}

	var hosts []NetworkHost
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		log.Printf("Failed to decode network manager response: %v", err)
		return ""
	}

	// Find matching MAC (case-insensitive)
	for _, h := range hosts {
		if strings.EqualFold(h.MACAddress, mac) {
			// Prefer hostname field, fall back to dns_name
			if h.Hostname != "" {
				return h.Hostname
			}
			if h.DNSName != "" {
				// Extract short hostname from FQDN (e.g., "server1.g10.lo" -> "server1")
				if idx := strings.Index(h.DNSName, "."); idx > 0 {
					return h.DNSName[:idx]
				}
				return h.DNSName
			}
		}
	}

	return ""
}

func handleAPIHostsAutoConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hosts, err := getHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	configured := 0
	for _, host := range hosts {
		if host.Hostname != "" && (host.IPMIIP == nil || *host.IPMIIP == "") {
			// Auto-configure IPMI - use hostname + IPMI domain
			shortName := host.Hostname
			if idx := strings.Index(host.Hostname, "."); idx > 0 {
				shortName = host.Hostname[:idx]
			}
			domain := ipmiDomain
			if domain == "" {
				domain = "g11.lo"
			}
			ipmiIP := shortName + "." + domain
			_, err := db.Exec(`UPDATE hosts SET ipmi_ip = ?, ipmi_username = 'ADMIN', ipmi_password = 'ADMIN' WHERE mac = ?`,
				ipmiIP, host.MAC)
			if err == nil {
				configured++
				logActivity("info", "config", &host, fmt.Sprintf("Auto-configured IPMI: %s", ipmiIP))
			}
		}
	}

	logActivity("info", "config", nil, fmt.Sprintf("Auto-configured IPMI for %d hosts", configured))
	w.Header().Set("HX-Trigger", "hostsUpdated")
	w.WriteHeader(http.StatusOK)
}

func handleAPIHostsLookupHostnames(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hosts, err := getHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	found := 0
	for _, host := range hosts {
		if host.Hostname == "" {
			hostname := lookupHostnameByMAC(host.MAC)
			if hostname != "" {
				_, err := db.Exec(`UPDATE hosts SET hostname = ? WHERE mac = ?`, hostname, host.MAC)
				if err == nil {
					found++
					logActivity("info", "config", &host, fmt.Sprintf("Discovered hostname: %s", hostname))
				}
			}
		}
	}

	logActivity("info", "config", nil, fmt.Sprintf("Discovered hostnames for %d hosts", found))
	w.Header().Set("HX-Trigger", "hostsUpdated")
	w.WriteHeader(http.StatusOK)
}

// Console API handlers
func handleAPIHostConsoleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		name = time.Now().Format("20060102-150405")
	}

	host, err := getHostByMAC(mac)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	if host.Hostname == "" {
		http.Error(w, "Host has no hostname", http.StatusBadRequest)
		return
	}

	if err := rotateConsoleLogs(host.Hostname, name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logActivity("info", "console", host, fmt.Sprintf("Rotated console logs with label %s", name))
	w.WriteHeader(http.StatusOK)
}

// ISO image API handler - add ISO as a bootable image
func handleAPIImageISO(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		// Add a new ISO image
		name := r.FormValue("name")
		isoURL := r.FormValue("url")

		if name == "" || isoURL == "" {
			http.Error(w, "name and url parameters required", http.StatusBadRequest)
			return
		}

		// Insert or update the image
		_, err := db.Exec(`INSERT INTO images (name, kernel, type) VALUES (?, ?, 'iso')
			ON CONFLICT(name) DO UPDATE SET kernel = ?, type = 'iso'`,
			name, isoURL, isoURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		logActivity("info", "image", nil, fmt.Sprintf("Added ISO image %s: %s", name, isoURL))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"name":    name,
			"iso_url": isoURL,
			"type":    "iso",
		})

	case "GET":
		// List all ISO images
		rows, err := db.Query(`SELECT name, kernel FROM images WHERE type = 'iso'`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var images []map[string]string
		for rows.Next() {
			var name, kernel string
			rows.Scan(&name, &kernel)
			images = append(images, map[string]string{"name": name, "url": kernel})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(images)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Workflow API handlers
func handleAPIWorkflows(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	workflows, err := getActiveWorkflows()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(workflows)
}

// Interface API handlers
func handleAPIHostInterfaces(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("host_id")
	if hostID == "" {
		http.Error(w, "host_id required", http.StatusBadRequest)
		return
	}

	var id int
	fmt.Sscanf(hostID, "%d", &id)

	interfaces, err := getHostInterfaces(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(interfaces)
}

func handleAPIHostInterface(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		r.ParseForm()
		action := r.URL.Query().Get("action")

		switch action {
		case "add":
			hostID := r.FormValue("host_id")
			mac := normalizeMAC(r.FormValue("mac"))
			name := r.FormValue("name")
			hostname := r.FormValue("hostname")
			use := r.FormValue("use") == "on" || r.FormValue("use") == "true" || r.FormValue("use") == "1"

			if hostID == "" || mac == "" {
				http.Error(w, "host_id and mac required", http.StatusBadRequest)
				return
			}

			_, err := db.Exec(`INSERT INTO host_interfaces (host_id, mac, name, hostname, use) VALUES (?, ?, ?, ?, ?)`,
				hostID, mac, name, hostname, use)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			logActivity("info", "config", nil, fmt.Sprintf("Added interface %s (%s) to host", name, mac))

		case "update":
			id := r.FormValue("id")
			use := r.FormValue("use") == "on" || r.FormValue("use") == "true" || r.FormValue("use") == "1"
			name := r.FormValue("name")
			hostname := r.FormValue("hostname")

			_, err := db.Exec(`UPDATE host_interfaces SET use = ?, name = ?, hostname = ? WHERE id = ?`,
				use, name, hostname, id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case "delete":
			id := r.URL.Query().Get("id")
			_, err := db.Exec(`DELETE FROM host_interfaces WHERE id = ?`, id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case "link":
			// Link an existing host's MAC to another host as an interface
			mac := normalizeMAC(r.FormValue("mac"))
			targetHostID := r.FormValue("target_host_id")
			name := r.FormValue("name")
			if name == "" {
				name = "b"
			}

			// Get the host that owns this MAC
			sourceHost, err := getHostByMAC(mac)
			if err != nil {
				http.Error(w, "Source host not found", http.StatusNotFound)
				return
			}

			// Add as interface to target host
			_, err = db.Exec(`INSERT INTO host_interfaces (host_id, mac, name, hostname, use) VALUES (?, ?, ?, ?, 0)`,
				targetHostID, mac, name, sourceHost.Hostname)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Delete the source host entry (it's now just an interface)
			db.Exec(`DELETE FROM hosts WHERE mac = ?`, mac)

			logActivity("info", "config", nil, fmt.Sprintf("Linked interface %s to host %s", mac, targetHostID))

		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}

		w.Header().Set("HX-Trigger", "hostsUpdated")
		w.WriteHeader(http.StatusOK)
	}
}

// Asset data API - for baremetalservices to report hardware info
func handleAPIAssetData(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		assetData, err := getAssetData(mac)
		if err != nil {
			http.Error(w, "Asset data not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(assetData)

	case "POST":
		var a AssetData
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.MAC = mac

		_, err := db.Exec(`INSERT INTO asset_data (mac, manufacturer, product_name, serial_number, bios_version, total_memory_gb, cpu_model, cpu_count, disk_info, network_info, last_updated)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(mac) DO UPDATE SET
				manufacturer = ?, product_name = ?, serial_number = ?, bios_version = ?,
				total_memory_gb = ?, cpu_model = ?, cpu_count = ?, disk_info = ?, network_info = ?,
				last_updated = CURRENT_TIMESTAMP`,
			a.MAC, a.Manufacturer, a.ProductName, a.SerialNumber, a.BIOSVersion, a.TotalMemoryGB, a.CPUModel, a.CPUCount, a.DiskInfo, a.NetworkInfo,
			a.Manufacturer, a.ProductName, a.SerialNumber, a.BIOSVersion, a.TotalMemoryGB, a.CPUModel, a.CPUCount, a.DiskInfo, a.NetworkInfo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		host, _ := getHostByMAC(mac)
		logActivity("info", "asset", host, "Asset data updated")

		w.WriteHeader(http.StatusOK)
	}
}

func handleAPIWorkflowCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`UPDATE workflows SET state = 'cancelled', updated = CURRENT_TIMESTAMP WHERE mac = ? AND state NOT IN ('completed', 'failed', 'cancelled')`, mac)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	host, _ := getHostByMAC(mac)
	logActivity("info", "workflow", host, "Workflow cancelled")

	w.Header().Set("HX-Trigger", "workflowsUpdated")
	w.WriteHeader(http.StatusOK)
}

// Activity log API handlers
func handleAPIActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	logs, err := getActivityLogs(100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(logs)
}

func handleActivityTable(w http.ResponseWriter, r *http.Request) {
	logs, _ := getActivityLogs(50)
	templates.ExecuteTemplate(w, "activity_log.html", logs)
}

func handleAPILogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs, err := getBootLogs(100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(logs)
}

// HTMX partial handlers
func handleHostsTable(w http.ResponseWriter, r *http.Request) {
	hosts, _ := getHosts()
	cdroms := getISCSICdroms()

	// Build a map of hostname → bootConfigRef from bmhMap
	configRefs := make(map[string]string)
	for _, h := range hosts {
		if h.Hostname != "" {
			configRefs[h.Hostname] = getHostBootConfigRef(h.Hostname)
		}
	}

	data := struct {
		Hosts      []Host
		CDROMs     []ISCSICdromInfo
		ConfigRefs map[string]string
	}{hosts, cdroms, configRefs}

	templates.ExecuteTemplate(w, "hosts_table.html", data)
}

func handleImagesTable(w http.ResponseWriter, r *http.Request) {
	images, _ := getImages()
	templates.ExecuteTemplate(w, "images_table.html", images)
}

func handleIPMITable(w http.ResponseWriter, r *http.Request) {
	hosts, _ := getHosts()
	templates.ExecuteTemplate(w, "ipmi_table.html", hosts)
}

func handleLogsTable(w http.ResponseWriter, r *http.Request) {
	logs, _ := getBootLogs(50)
	templates.ExecuteTemplate(w, "logs_table.html", logs)
}

func handleHostDetail(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
		return
	}

	host, err := getHostByMAC(mac)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	assetData, _ := getAssetData(mac)          // May be nil if no asset data
	interfaces, _ := getHostInterfaces(host.ID) // Get all interfaces for this host

	data := struct {
		Host       *Host
		AssetData  *AssetData
		Interfaces []HostInterface
	}{host, assetData, interfaces}

	templates.ExecuteTemplate(w, "host_detail.html", data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Prevent browser caching
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	hosts, _ := getHosts()
	images, _ := getImages()
	cdroms := getISCSICdroms()
	logs, _ := getBootLogs(20)

	// Build a map of hostname → bootConfigRef from bmhMap
	configRefs := make(map[string]string)
	for _, h := range hosts {
		if h.Hostname != "" {
			configRefs[h.Hostname] = getHostBootConfigRef(h.Hostname)
		}
	}

	data := struct {
		Hosts      []Host
		Images     []Image
		CDROMs     []ISCSICdromInfo
		ConfigRefs map[string]string
		Logs       []BootLog
		Version    string
	}{hosts, images, cdroms, configRefs, logs, Version}

	templates.ExecuteTemplate(w, "index.html", data)
}

// Boot cycle presets
func handleAPICyclePreset(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	preset := r.URL.Query().Get("preset")

	var cycle []string
	switch preset {
	case "bios_update":
		cycle = []string{"biosupdate", "baremetalservices"}
	case "disk_wipe":
		cycle = []string{"baremetalservices"} // baremetalservices will call disk wipe API then reboot
	case "openshift_prep":
		cycle = []string{"baremetalservices", "localboot"} // wipe disk, then local boot for OpenShift
	default:
		http.Error(w, "unknown preset", http.StatusBadRequest)
		return
	}

	cycleJSON, _ := json.Marshal(cycle)
	_, err := db.Exec(`UPDATE hosts SET cycle_images = ?, cycle_index = 0 WHERE mac = ?`, string(cycleJSON), mac)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Trigger", "hostsUpdated")
	w.WriteHeader(http.StatusOK)
}

// Redfish API handlers for OpenShift Bare Metal Operator compatibility
func handleRedfishRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"@odata.type": "#ServiceRoot.v1_5_0.ServiceRoot",
		"@odata.id":   "/redfish/v1",
		"Id":          "RootService",
		"Name":        "PXE Manager Redfish Service",
		"RedfishVersion": "1.6.0",
		"Systems": map[string]string{
			"@odata.id": "/redfish/v1/Systems",
		},
	})
}

func handleRedfishSystems(w http.ResponseWriter, r *http.Request) {
	hosts, _ := getHosts()

	members := make([]map[string]string, 0)
	for _, h := range hosts {
		if h.Hostname != "" && h.IPMIIP != nil {
			members = append(members, map[string]string{
				"@odata.id": fmt.Sprintf("/redfish/v1/Systems/%s", h.Hostname),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"@odata.type":      "#ComputerSystemCollection.ComputerSystemCollection",
		"@odata.id":        "/redfish/v1/Systems",
		"Name":             "Computer System Collection",
		"Members@odata.count": len(members),
		"Members":          members,
	})
}

func handleRedfishSystem(w http.ResponseWriter, r *http.Request) {
	// Extract hostname from path: /redfish/v1/Systems/{hostname}
	path := r.URL.Path
	parts := strings.Split(strings.TrimPrefix(path, "/redfish/v1/Systems/"), "/")
	hostname := parts[0]

	if hostname == "" {
		http.Error(w, "System ID required", http.StatusBadRequest)
		return
	}

	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "System not found", http.StatusNotFound)
		return
	}

	// Get power state
	powerState := "Off"
	if host.IPMIIP != nil && *host.IPMIIP != "" {
		status, err := ipmiPowerStatus(host)
		if err == nil && status == "on" {
			powerState = "On"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"@odata.type": "#ComputerSystem.v1_13_0.ComputerSystem",
		"@odata.id":   fmt.Sprintf("/redfish/v1/Systems/%s", hostname),
		"Id":          hostname,
		"Name":        hostname,
		"PowerState":  powerState,
		"Boot": map[string]interface{}{
			"BootSourceOverrideEnabled": "Once",
			"BootSourceOverrideTarget":  "Pxe",
			"BootSourceOverrideTarget@Redfish.AllowableValues": []string{"None", "Pxe", "Hdd"},
		},
		"Actions": map[string]interface{}{
			"#ComputerSystem.Reset": map[string]interface{}{
				"target": fmt.Sprintf("/redfish/v1/Systems/%s/Actions/ComputerSystem.Reset", hostname),
				"ResetType@Redfish.AllowableValues": []string{"On", "ForceOff", "ForceRestart", "PushPowerButton"},
			},
		},
	})
}

func handleRedfishSystemAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract hostname from path: /redfish/v1/Systems/{hostname}/Actions/ComputerSystem.Reset
	path := r.URL.Path
	parts := strings.Split(strings.TrimPrefix(path, "/redfish/v1/Systems/"), "/")
	hostname := parts[0]

	if hostname == "" {
		http.Error(w, "System ID required", http.StatusBadRequest)
		return
	}

	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "System not found", http.StatusNotFound)
		return
	}

	if host.IPMIIP == nil || *host.IPMIIP == "" {
		http.Error(w, "IPMI not configured", http.StatusBadRequest)
		return
	}

	var body struct {
		ResetType string `json:"ResetType"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Clear stale sessions before operation
	clearDellSessions(host)

	var actionErr error
	switch body.ResetType {
	case "On":
		actionErr = startPowerTransition(host, "power_on")
	case "ForceOff", "GracefulShutdown":
		actionErr = startPowerTransition(host, "power_off")
	case "ForceRestart", "GracefulRestart":
		actionErr = startPowerTransition(host, "restart")
	case "PushPowerButton":
		status, _ := ipmiPowerStatus(host)
		if status == "on" {
			actionErr = startPowerTransition(host, "power_off")
		} else {
			actionErr = startPowerTransition(host, "power_on")
		}
	default:
		http.Error(w, fmt.Sprintf("Unsupported ResetType: %s", body.ResetType), http.StatusBadRequest)
		return
	}

	// Clear sessions after operation
	go clearDellSessions(host)

	if actionErr != nil {
		http.Error(w, actionErr.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Router for /redfish/v1/Systems/{hostname}/...
func handleRedfishSystemRouter(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/redfish/v1/Systems/")
	parts := strings.Split(path, "/")
	hostname := parts[0]

	if hostname == "" {
		handleRedfishSystems(w, r)
		return
	}

	if len(parts) == 1 {
		// GET/PATCH /redfish/v1/Systems/{hostname}
		if r.Method == "PATCH" {
			handleRedfishSystemPatch(w, r, hostname)
		} else {
			handleRedfishSystem(w, r)
		}
		return
	}

	// Route based on sub-path
	subPath := strings.Join(parts[1:], "/")
	switch {
	case subPath == "Actions/ComputerSystem.Reset":
		handleRedfishSystemAction(w, r)
	case strings.HasPrefix(subPath, "VirtualMedia"):
		handleRedfishVirtualMedia(w, r, hostname, subPath)
	case subPath == "Thermal":
		handleRedfishThermal(w, r, hostname)
	case subPath == "Power":
		handleRedfishPower(w, r, hostname)
	default:
		http.NotFound(w, r)
	}
}

func handleRedfishSystemPatch(w http.ResponseWriter, r *http.Request, hostname string) {
	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "System not found", http.StatusNotFound)
		return
	}

	var body struct {
		Boot struct {
			BootSourceOverrideTarget  string `json:"BootSourceOverrideTarget"`
			BootSourceOverrideEnabled string `json:"BootSourceOverrideEnabled"`
		} `json:"Boot"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if host.IPMIIP != nil && *host.IPMIIP != "" {
		switch body.Boot.BootSourceOverrideTarget {
		case "Pxe":
			ipmiSetBootPXE(host)
			logActivity("info", "redfish", host, "Set boot to PXE via Redfish API")
		case "Hdd":
			ipmiSetBootDisk(host)
			logActivity("info", "redfish", host, "Set boot to HDD via Redfish API")
		case "Cd":
			// Virtual CD - will be handled via VirtualMedia
			logActivity("info", "redfish", host, "Set boot to CD via Redfish API")
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// Virtual Media for ISO mounting
func handleRedfishVirtualMedia(w http.ResponseWriter, r *http.Request, hostname, subPath string) {
	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "System not found", http.StatusNotFound)
		return
	}

	parts := strings.Split(subPath, "/")

	// GET /VirtualMedia - list virtual media devices
	if len(parts) == 1 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"@odata.type":         "#VirtualMediaCollection.VirtualMediaCollection",
			"@odata.id":           fmt.Sprintf("/redfish/v1/Systems/%s/VirtualMedia", hostname),
			"Name":                "Virtual Media Collection",
			"Members@odata.count": 1,
			"Members": []map[string]string{
				{"@odata.id": fmt.Sprintf("/redfish/v1/Systems/%s/VirtualMedia/CD1", hostname)},
			},
		})
		return
	}

	mediaID := parts[1]

	// Actions on virtual media
	if len(parts) >= 3 && parts[2] == "Actions" {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		action := ""
		if len(parts) >= 4 {
			action = parts[3]
		}

		switch action {
		case "VirtualMedia.InsertMedia":
			var body struct {
				Image          string `json:"Image"`
				Inserted       bool   `json:"Inserted"`
				WriteProtected bool   `json:"WriteProtected"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			// Store the ISO URL for this host
			db.Exec(`UPDATE hosts SET virtual_media_url = ? WHERE hostname = ?`, body.Image, hostname)
			logActivity("info", "redfish", host, fmt.Sprintf("Inserted virtual media: %s", body.Image))

			w.WriteHeader(http.StatusNoContent)
			return

		case "VirtualMedia.EjectMedia":
			db.Exec(`UPDATE hosts SET virtual_media_url = NULL WHERE hostname = ?`, hostname)
			logActivity("info", "redfish", host, "Ejected virtual media")
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// GET /VirtualMedia/{id}
	var virtualMediaURL sql.NullString
	db.QueryRow(`SELECT virtual_media_url FROM hosts WHERE hostname = ?`, hostname).Scan(&virtualMediaURL)

	inserted := virtualMediaURL.Valid && virtualMediaURL.String != ""
	imageURL := ""
	if inserted {
		imageURL = virtualMediaURL.String
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"@odata.type":    "#VirtualMedia.v1_3_0.VirtualMedia",
		"@odata.id":      fmt.Sprintf("/redfish/v1/Systems/%s/VirtualMedia/%s", hostname, mediaID),
		"Id":             mediaID,
		"Name":           "Virtual CD",
		"MediaTypes":     []string{"CD", "DVD"},
		"Image":          imageURL,
		"Inserted":       inserted,
		"WriteProtected": true,
		"Actions": map[string]interface{}{
			"#VirtualMedia.InsertMedia": map[string]string{
				"target": fmt.Sprintf("/redfish/v1/Systems/%s/VirtualMedia/%s/Actions/VirtualMedia.InsertMedia", hostname, mediaID),
			},
			"#VirtualMedia.EjectMedia": map[string]string{
				"target": fmt.Sprintf("/redfish/v1/Systems/%s/VirtualMedia/%s/Actions/VirtualMedia.EjectMedia", hostname, mediaID),
			},
		},
	})
}

// Thermal/temperature data
func handleRedfishThermal(w http.ResponseWriter, r *http.Request, hostname string) {
	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "System not found", http.StatusNotFound)
		return
	}

	temperatures := []map[string]interface{}{}
	fans := []map[string]interface{}{}

	// Get sensor data via IPMI
	if host.IPMIIP != nil && *host.IPMIIP != "" {
		client, err := getIPMIClient(host)
		if err == nil {
			defer client.Close(context.Background())

			sensors, err := client.GetSensors(context.Background())
			if err == nil {
				tempIdx := 0
				fanIdx := 0
				for _, sensor := range sensors {
					// Temperature sensors (SensorType 0x01)
					if sensor.SensorType == 0x01 {
						temperatures = append(temperatures, map[string]interface{}{
							"@odata.id":      fmt.Sprintf("/redfish/v1/Systems/%s/Thermal#/Temperatures/%d", hostname, tempIdx),
							"MemberId":       fmt.Sprintf("%d", tempIdx),
							"Name":           sensor.Name,
							"ReadingCelsius": sensor.Value,
							"Status":         map[string]string{"State": "Enabled", "Health": "OK"},
						})
						tempIdx++
					}
					// Fan sensors (SensorType 0x04)
					if sensor.SensorType == 0x04 {
						fans = append(fans, map[string]interface{}{
							"@odata.id":    fmt.Sprintf("/redfish/v1/Systems/%s/Thermal#/Fans/%d", hostname, fanIdx),
							"MemberId":     fmt.Sprintf("%d", fanIdx),
							"Name":         sensor.Name,
							"Reading":      int(sensor.Value),
							"ReadingUnits": "RPM",
							"Status":       map[string]string{"State": "Enabled", "Health": "OK"},
						})
						fanIdx++
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"@odata.type":  "#Thermal.v1_6_0.Thermal",
		"@odata.id":    fmt.Sprintf("/redfish/v1/Systems/%s/Thermal", hostname),
		"Id":           "Thermal",
		"Name":         "Thermal",
		"Temperatures": temperatures,
		"Fans":         fans,
	})
}

// Power data
func handleRedfishPower(w http.ResponseWriter, r *http.Request, hostname string) {
	host, err := getHostByHostname(hostname)
	if err != nil {
		http.Error(w, "System not found", http.StatusNotFound)
		return
	}

	powerSupplies := []map[string]interface{}{}
	powerControl := []map[string]interface{}{}

	// Get sensor data via IPMI
	if host.IPMIIP != nil && *host.IPMIIP != "" {
		client, err := getIPMIClient(host)
		if err == nil {
			defer client.Close(context.Background())

			sensors, err := client.GetSensors(context.Background())
			if err == nil {
				psuIdx := 0
				pwrIdx := 0
				for _, sensor := range sensors {
					// Power Supply sensors (SensorType 0x08)
					if sensor.SensorType == 0x08 {
						powerSupplies = append(powerSupplies, map[string]interface{}{
							"@odata.id":        fmt.Sprintf("/redfish/v1/Systems/%s/Power#/PowerSupplies/%d", hostname, psuIdx),
							"MemberId":         fmt.Sprintf("%d", psuIdx),
							"Name":             sensor.Name,
							"PowerOutputWatts": sensor.Value,
							"Status":           map[string]string{"State": "Enabled", "Health": "OK"},
						})
						psuIdx++
					}
					// Current/Power sensors (SensorType 0x03 for current, 0x08 for power)
					if sensor.SensorType == 0x03 || (sensor.SensorType == 0x08 && sensor.SensorUnit.BaseUnit == 0x06) {
						powerControl = append(powerControl, map[string]interface{}{
							"@odata.id":            fmt.Sprintf("/redfish/v1/Systems/%s/Power#/PowerControl/%d", hostname, pwrIdx),
							"MemberId":             fmt.Sprintf("%d", pwrIdx),
							"Name":                 sensor.Name,
							"PowerConsumedWatts":   sensor.Value,
							"Status":               map[string]string{"State": "Enabled", "Health": "OK"},
						})
						pwrIdx++
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"@odata.type":   "#Power.v1_6_0.Power",
		"@odata.id":     fmt.Sprintf("/redfish/v1/Systems/%s/Power", hostname),
		"Id":            "Power",
		"Name":          "Power",
		"PowerSupplies": powerSupplies,
		"PowerControl":  powerControl,
	})
}

// ─── Boot File Initialization ───────────────────────────────────────────────

const defaultsDir = "/opt/pxemanager/defaults"
const tftpbootDir = "/tftpboot"
const defaultRegistryURL = "http://registry.gt.lo:5000"
const dataImageRepo = "pxemanager-data"
const dataImageTag = "edge"
const digestFile = ".data-digest"

// dataFiles are the large boot files stored in the pxemanager-data image
var dataFiles = []string{
	"vmlinuz",
	"initramfs",
	"fedora-vmlinuz",
	"fedora-initrd.img",
	"coreos-kernel",
	"coreos-initramfs",
	"coreos-rootfs.img",
	"stormbase.iso",
}

// ensureBootFiles copies small config files from /opt/pxemanager/defaults to
// /tftpboot, then pulls any missing large boot files from the pxemanager-data
// image in the container registry.
func ensureBootFiles() {
	os.MkdirAll(tftpbootDir, 0755)

	// Step 1: Copy small files from defaults dir (baked into app image)
	entries, err := os.ReadDir(defaultsDir)
	if err != nil {
		log.Printf("Boot files: defaults dir not available: %v", err)
	} else {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			src := filepath.Join(defaultsDir, entry.Name())
			dst := filepath.Join(tftpbootDir, entry.Name())

			srcInfo, err := os.Stat(src)
			if err != nil {
				log.Printf("Boot files: failed to stat %s: %v", src, err)
				continue
			}

			if dstInfo, err := os.Stat(dst); err == nil {
				if srcInfo.Size() == dstInfo.Size() {
					continue
				}
				log.Printf("Boot files: %s changed (size %d -> %d), replacing", entry.Name(), dstInfo.Size(), srcInfo.Size())
			}

			srcFile, err := os.Open(src)
			if err != nil {
				log.Printf("Boot files: failed to open %s: %v", src, err)
				continue
			}
			dstFile, err := os.Create(dst)
			if err != nil {
				srcFile.Close()
				log.Printf("Boot files: failed to create %s: %v", dst, err)
				continue
			}
			n, err := io.Copy(dstFile, srcFile)
			srcFile.Close()
			dstFile.Close()
			if err != nil {
				log.Printf("Boot files: failed to copy %s: %v", dst, err)
				continue
			}
			log.Printf("Boot files: installed %s (%d MB)", entry.Name(), n/1024/1024)
		}
	}

	// Step 2: Check which large files are missing from /tftpboot
	var missing []string
	for _, f := range dataFiles {
		dst := filepath.Join(tftpbootDir, f)
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		log.Printf("Boot files: all data files present")
		return
	}
	log.Printf("Boot files: missing %d data files: %v", len(missing), missing)

	// Step 3: Pull from registry
	pullDataFiles(missing)
}

// pullDataFiles fetches missing large boot files from the pxemanager-data
// image in the container registry using the Docker Registry HTTP API v2.
func pullDataFiles(missing []string) {
	registryURL := os.Getenv("REGISTRY_URL")
	if registryURL == "" {
		registryURL = defaultRegistryURL
	}
	registryURL = strings.TrimRight(registryURL, "/")

	// Get manifest to find the layer digest
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", registryURL, dataImageRepo, dataImageTag)
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		log.Printf("Boot files: failed to create manifest request: %v", err)
		return
	}
	// Accept Docker manifest v2 schema 2
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Boot files: failed to fetch manifest from %s: %v", manifestURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Boot files: registry returned %d for manifest", resp.StatusCode)
		return
	}

	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			MediaType string `json:"mediaType"`
		} `json:"layers"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Boot files: failed to read manifest: %v", err)
		return
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		log.Printf("Boot files: failed to parse manifest: %v", err)
		return
	}

	// Check if digest changed since last pull
	currentDigest := resp.Header.Get("Docker-Content-Digest")
	if currentDigest == "" && len(manifest.Layers) > 0 {
		currentDigest = manifest.Layers[0].Digest
	}
	savedDigest, _ := os.ReadFile(filepath.Join(tftpbootDir, digestFile))
	if string(savedDigest) == currentDigest && currentDigest != "" {
		log.Printf("Boot files: data image digest unchanged, skipping pull")
		return
	}

	// Build set of missing files for quick lookup
	missingSet := make(map[string]bool)
	for _, f := range missing {
		missingSet[f] = true
	}

	// Pull each layer and extract data files
	for i, layer := range manifest.Layers {
		log.Printf("Boot files: pulling layer %d/%d (%s, %d MB)", i+1, len(manifest.Layers), layer.Digest[:19], layer.Size/1024/1024)

		blobURL := fmt.Sprintf("%s/v2/%s/blobs/%s", registryURL, dataImageRepo, layer.Digest)
		blobResp, err := http.Get(blobURL)
		if err != nil {
			log.Printf("Boot files: failed to fetch blob %s: %v", layer.Digest[:19], err)
			return
		}
		if blobResp.StatusCode != http.StatusOK {
			blobResp.Body.Close()
			log.Printf("Boot files: registry returned %d for blob %s", blobResp.StatusCode, layer.Digest[:19])
			return
		}

		err = extractDataLayer(blobResp.Body, missingSet)
		blobResp.Body.Close()
		if err != nil {
			log.Printf("Boot files: failed to extract layer: %v", err)
			return
		}

		// If all missing files found, stop pulling layers
		if len(missingSet) == 0 {
			break
		}
	}

	// Save digest for next startup
	if currentDigest != "" {
		os.WriteFile(filepath.Join(tftpbootDir, digestFile), []byte(currentDigest), 0644)
		log.Printf("Boot files: saved data digest %s", currentDigest[:19])
	}
}

// extractDataLayer reads a gzip-compressed tar layer and extracts files from
// /data/ into /tftpboot/. Only extracts files in the missingSet and removes
// them from the set as they are extracted.
func extractDataLayer(r io.Reader, missingSet map[string]bool) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}

		// Files are at /data/<filename> in the layer
		name := strings.TrimPrefix(hdr.Name, "data/")
		name = strings.TrimPrefix(name, "./data/")
		if name == hdr.Name || name == "" || hdr.Typeflag != tar.TypeReg {
			continue
		}

		if !missingSet[name] {
			continue
		}

		dst := filepath.Join(tftpbootDir, name)
		f, err := os.Create(dst)
		if err != nil {
			return fmt.Errorf("create %s: %w", dst, err)
		}
		n, err := io.Copy(f, tr)
		f.Close()
		if err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
		log.Printf("Boot files: extracted %s (%d MB)", name, n/1024/1024)
		delete(missingSet, name)
	}
	return nil
}

// ─── Network CRD Types ──────────────────────────────────────────────────────

type networkDHCPReservation struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

type networkDHCP struct {
	Enabled      bool                     `json:"enabled"`
	NextServer   string                   `json:"nextServer"`
	BootFile     string                   `json:"bootFile"`
	Reservations []networkDHCPReservation  `json:"reservations"`
}

type networkDNS struct {
	Zone string `json:"zone"`
}

type networkSpec struct {
	Type string      `json:"type"` // "data", "ipmi", "external"
	DHCP networkDHCP `json:"dhcp"`
	DNS  networkDNS  `json:"dns"`
}

type networkCRD struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec networkSpec `json:"spec"`
}

type networkList struct {
	Items []networkCRD `json:"items"`
}

// ipmiDomain is the DNS zone for the IPMI network (e.g. "g11.lo"), used by auto-configure fallback
var ipmiDomain string

// ─── BMH Sync Types ─────────────────────────────────────────────────────────

type bmhMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type bmhBMC struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type bmhSpec struct {
	BMC            bmhBMC `json:"bmc"`
	BootMACAddress string `json:"bootMACAddress"`
	Online         *bool  `json:"online,omitempty"`
	Image          string `json:"image,omitempty"`
	BootConfigRef  string `json:"bootConfigRef,omitempty"`
	Network        string `json:"network,omitempty"`
	IP             string `json:"ip,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
}

type bmhStatus struct {
	Phase     string `json:"phase"`
	PoweredOn bool   `json:"poweredOn"`
	IP        string `json:"ip,omitempty"`
}

type bmhObject struct {
	Metadata bmhMetadata `json:"metadata"`
	Spec     bmhSpec     `json:"spec"`
	Status   bmhStatus   `json:"status,omitempty"`
}

type bmhList struct {
	Items []bmhObject `json:"items"`
}

type bmhWatchEvent struct {
	Type   string    `json:"type"`
	Object bmhObject `json:"object"`
}

// ─── iSCSI CDROM Types ──────────────────────────────────────────────────────

type iscsiCdromSpec struct {
	ISOFile     string   `json:"isoFile"`
	Description string   `json:"description,omitempty"`
	ReadOnly    bool     `json:"readOnly"`
	BootConfigs []string `json:"bootConfigs,omitempty"`
}

type iscsiCdromStatus struct {
	Phase      string `json:"phase"`
	ISOPath    string `json:"isoPath"`
	ISOSize    int64  `json:"isoSize,omitempty"`
	TargetIQN  string `json:"targetIQN"`
	PortalIP   string `json:"portalIP"`
	PortalPort int    `json:"portalPort"`
}

type iscsiCdromObject struct {
	Metadata bmhMetadata      `json:"metadata"`
	Spec     iscsiCdromSpec   `json:"spec"`
	Status   iscsiCdromStatus `json:"status,omitempty"`
}

type iscsiCdromList struct {
	Items []iscsiCdromObject `json:"items"`
}

type iscsiCdromWatchEvent struct {
	Type   string           `json:"type"`
	Object iscsiCdromObject `json:"object"`
}

// iscsiCdromMap tracks iSCSI CDROMs: name → iscsiCdromObject
var iscsiCdromMap sync.Map

// ISCSICdromInfo is a simplified view of an iSCSI CDROM for templates
type ISCSICdromInfo struct {
	Name        string
	Description string
	TargetIQN   string
	PortalIP    string
	Phase       string
	BootConfigs []string
}

// getISCSICdroms returns all cached iSCSI CDROMs as template-friendly structs
func getISCSICdroms() []ISCSICdromInfo {
	var cdroms []ISCSICdromInfo
	iscsiCdromMap.Range(func(key, value interface{}) bool {
		cdrom := value.(iscsiCdromObject)
		cdroms = append(cdroms, ISCSICdromInfo{
			Name:        cdrom.Metadata.Name,
			Description: cdrom.Spec.Description,
			TargetIQN:   cdrom.Status.TargetIQN,
			PortalIP:    cdrom.Status.PortalIP,
			Phase:       cdrom.Status.Phase,
			BootConfigs: cdrom.Spec.BootConfigs,
		})
		return true
	})
	sort.Slice(cdroms, func(i, j int) bool { return cdroms[i].Name < cdroms[j].Name })
	return cdroms
}

// getHostBootConfigRef returns the bootConfigRef for a host from bmhMap
func getHostBMHImage(hostname string) string {
	val, ok := bmhMap.Load(hostname)
	if !ok {
		return ""
	}
	bmh := val.(bmhObject)
	return bmh.Spec.Image
}

func getHostBootConfigRef(hostname string) string {
	val, ok := bmhMap.Load(hostname)
	if !ok {
		return ""
	}
	bmh := val.(bmhObject)
	return bmh.Spec.BootConfigRef
}

const bmhCachePath = "/var/lib/pxemanager/bmh-cache.json"

func loadBMHCache() []bmhObject {
	data, err := os.ReadFile(bmhCachePath)
	if err != nil {
		return nil
	}
	var items []bmhObject
	if err := json.Unmarshal(data, &items); err != nil {
		log.Printf("BMH cache: failed to parse: %v", err)
		return nil
	}
	return items
}

func saveBMHCache(items []bmhObject) {
	data, err := json.Marshal(items)
	if err != nil {
		log.Printf("BMH cache: failed to marshal: %v", err)
		return
	}
	dir := filepath.Dir(bmhCachePath)
	tmp := filepath.Join(dir, ".bmh-cache.tmp")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Printf("BMH cache: failed to write temp: %v", err)
		return
	}
	if err := os.Rename(tmp, bmhCachePath); err != nil {
		log.Printf("BMH cache: failed to rename: %v", err)
	}
}

func syncBMHToHosts(bmhs []bmhObject) {
	for _, bmh := range bmhs {
		mac := normalizeMAC(bmh.Spec.BootMACAddress)
		if mac == "" {
			continue
		}

		hostname := bmh.Metadata.Name
		// Skip "b" variant devices (e.g. server1b, server30b)
		if strings.HasSuffix(hostname, "b") {
			continue
		}
		bmhMap.Store(hostname, bmh)
		image := bmh.Spec.Image
		if image == "" {
			image = "localboot"
		}

		// BMH has the IPMI IP in bmc.address and credentials
		ipmiIP := bmh.Spec.BMC.Address
		bmcUser := defaultStr(bmh.Spec.BMC.Username, "ADMIN")
		bmcPass := defaultStr(bmh.Spec.BMC.Password, "ADMIN")

		existing, err := getHostByMAC(mac)
		if err != nil {
			// Host doesn't exist, create it
			_, err := db.Exec(`INSERT INTO hosts (mac, hostname, current_image, ipmi_ip, ipmi_username, ipmi_password) VALUES (?, ?, ?, ?, ?, ?)`,
				mac, hostname, image,
				nullStr(ipmiIP),
				bmcUser,
				bmcPass)
			if err != nil {
				log.Printf("BMH sync: failed to insert host %s: %v", hostname, err)
				continue
			}
			log.Printf("BMH sync: created host %s (mac=%s, ipmi=%s)", hostname, mac, ipmiIP)

			// Create primary interface
			host, err := getHostByMAC(mac)
			if err == nil {
				db.Exec(`INSERT OR IGNORE INTO host_interfaces (host_id, mac, name, hostname) VALUES (?, ?, 'a', ?)`,
					host.ID, mac, hostname)
			}

			logActivity("info", "bmh-sync", &Host{MAC: mac, Hostname: hostname}, fmt.Sprintf("Host created from BMH %s/%s", bmh.Metadata.Namespace, bmh.Metadata.Name))
			continue
		}

		// Host exists, sync changes from BMH (source of truth)
		changed := false
		updates := []string{}
		args := []interface{}{}

		if existing.Hostname != hostname {
			updates = append(updates, "hostname = ?")
			args = append(args, hostname)
			changed = true
		}
		// Sync current_image from BMH spec.image (CRD is source of truth)
		if image != existing.CurrentImage {
			updates = append(updates, "current_image = ?")
			args = append(args, image)
			changed = true
		}
		if ipmiIP != "" && (existing.IPMIIP == nil || *existing.IPMIIP != ipmiIP) {
			updates = append(updates, "ipmi_ip = ?")
			args = append(args, ipmiIP)
			changed = true
		}
		if bmcUser != existing.IPMIUsername {
			updates = append(updates, "ipmi_username = ?")
			args = append(args, bmcUser)
			changed = true
		}
		if bmcPass != existing.IPMIPassword {
			updates = append(updates, "ipmi_password = ?")
			args = append(args, bmcPass)
			changed = true
		}

		if changed {
			args = append(args, mac)
			query := fmt.Sprintf("UPDATE hosts SET %s WHERE mac = ?", strings.Join(updates, ", "))
			if _, err := db.Exec(query, args...); err != nil {
				log.Printf("BMH sync: failed to update host %s: %v", hostname, err)
				continue
			}
			log.Printf("BMH sync: updated host %s (mac=%s)", hostname, mac)
			logActivity("info", "bmh-sync", existing, fmt.Sprintf("Host updated from BMH: %s", strings.Join(updates, ", ")))
		}
	}

	// Remove hosts that no longer have a BMH (only if we got a real list, not empty/failed)
	if len(bmhs) < 2 {
		return // Don't cleanup on empty or near-empty lists — likely a fetch failure
	}

	bmhMACs := make(map[string]bool)
	for _, bmh := range bmhs {
		mac := normalizeMAC(bmh.Spec.BootMACAddress)
		if mac != "" {
			bmhMACs[mac] = true
		}
	}

	rows, err := db.Query(`SELECT id, mac, hostname FROM hosts`)
	if err != nil {
		return
	}
	defer rows.Close()

	var toDelete []struct {
		id       int
		mac      string
		hostname string
	}
	for rows.Next() {
		var id int
		var mac, hostname string
		if err := rows.Scan(&id, &mac, &hostname); err != nil {
			continue
		}
		if !bmhMACs[normalizeMAC(mac)] {
			toDelete = append(toDelete, struct {
				id       int
				mac      string
				hostname string
			}{id, mac, hostname})
		}
	}

	for _, h := range toDelete {
		db.Exec(`DELETE FROM host_interfaces WHERE host_id = ?`, h.id)
		db.Exec(`DELETE FROM hosts WHERE id = ?`, h.id)
		bmhMap.Delete(h.hostname)
		log.Printf("BMH sync: removed host %s (mac=%s) — no longer in BMH", h.hostname, h.mac)
		logActivity("info", "bmh-sync", &Host{MAC: h.mac, Hostname: h.hostname}, "Host removed — BMH deleted")
	}
}

// updateBMHPowerStatus patches the BMH poweredOn status in mkube
func updateBMHPowerStatus(hostname string, poweredOn bool) {
	if activeMkubeURL == "" {
		return
	}
	val, ok := bmhMap.Load(hostname)
	if !ok {
		return
	}
	bmh := val.(bmhObject)
	ns := bmh.Metadata.Namespace
	if ns == "" {
		return
	}

	patch := fmt.Sprintf(`{"status":{"poweredOn":%t}}`, poweredOn)
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/baremetalhosts/%s", activeMkubeURL, ns, hostname)
	req, err := http.NewRequest("PATCH", url, strings.NewReader(patch))
	if err != nil {
		log.Printf("BMH status: failed to create PATCH request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("BMH status: failed to PATCH %s: %v", hostname, err)
		return
	}
	resp.Body.Close()
	log.Printf("BMH status: updated %s/%s poweredOn=%t", ns, hostname, poweredOn)
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// fetchNetworks fetches Network CRDs from mkube to discover the IPMI domain
// (used as fallback by auto-configure when a host has no IPMI IP).
func fetchNetworks(mkubeURL string) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(mkubeURL + "/api/v1/networks")
	if err != nil {
		log.Printf("Networks: fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var list networkList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Printf("Networks: decode failed: %v", err)
		return
	}

	for _, net := range list.Items {
		if net.Spec.Type == "ipmi" && net.Spec.DNS.Zone != "" {
			ipmiDomain = net.Spec.DNS.Zone
			log.Printf("Networks: IPMI domain = %s", ipmiDomain)
			break
		}
	}
}

func bmhWatcher(ctx context.Context, mkubeURL string) {
	log.Printf("BMH watcher: starting (mkube=%s)", mkubeURL)

	// Fetch networks for IPMI domain (used by auto-configure fallback)
	fetchNetworks(mkubeURL)

	// Step 1: Load cached data for fast startup
	cached := loadBMHCache()
	if len(cached) > 0 {
		log.Printf("BMH watcher: loaded %d hosts from cache", len(cached))
		syncBMHToHosts(cached)
	}

	// Step 2: Fetch current data from mkube
	fetchAndSync := func() {
		items := fetchBMHList(mkubeURL)
		if items != nil {
			syncBMHToHosts(items)
			saveBMHCache(items)
			log.Printf("BMH watcher: synced %d hosts from mkube", len(items))
		}
	}
	fetchAndSync()

	// Step 3: Periodic full sync in background
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fetchAndSync()
			}
		}
	}()

	// Step 4: Watch with reconnect loop
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watchBMHStream(ctx, mkubeURL)

		// Watch disconnected, wait before reconnecting
		log.Printf("BMH watcher: watch disconnected, will reconnect in 5s")
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			fetchAndSync()
		}
	}
}

func fetchBMHList(mkubeURL string) []bmhObject {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(mkubeURL + "/api/v1/baremetalhosts")
	if err != nil {
		log.Printf("BMH watcher: fetch failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var list bmhList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Printf("BMH watcher: decode failed: %v", err)
		return nil
	}
	return list.Items
}

func watchBMHStream(ctx context.Context, mkubeURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", mkubeURL+"/api/v1/baremetalhosts?watch=true", nil)
	if err != nil {
		log.Printf("BMH watcher: watch request failed: %v", err)
		return
	}

	watchClient := &http.Client{}
	resp, err := watchClient.Do(req)
	if err != nil {
		log.Printf("BMH watcher: watch connect failed: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("BMH watcher: watch connected")

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event bmhWatchEvent
		if err := json.Unmarshal(line, &event); err != nil {
			log.Printf("BMH watcher: decode event failed: %v", err)
			continue
		}

		switch event.Type {
		case "ADDED", "MODIFIED":
			syncBMHToHosts([]bmhObject{event.Object})
		case "DELETED":
			mac := normalizeMAC(event.Object.Spec.BootMACAddress)
			if mac != "" {
				log.Printf("BMH watcher: host deleted: %s (mac=%s)", event.Object.Metadata.Name, mac)
				logActivity("info", "bmh-sync", nil, fmt.Sprintf("BMH deleted: %s (mac=%s)", event.Object.Metadata.Name, mac))
			}
		}
	}
}

// ─── iSCSI CDROM Watcher ────────────────────────────────────────────────────

func iscsiCdromWatcher(ctx context.Context, mkubeURL string) {
	log.Printf("iSCSI CDROM watcher: starting (mkube=%s)", mkubeURL)

	fetchAndSync := func() {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(mkubeURL + "/api/v1/iscsi-cdroms")
		if err != nil {
			log.Printf("iSCSI CDROM watcher: fetch failed: %v", err)
			return
		}
		defer resp.Body.Close()

		var list iscsiCdromList
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			log.Printf("iSCSI CDROM watcher: decode failed: %v", err)
			return
		}

		for _, cdrom := range list.Items {
			iscsiCdromMap.Store(cdrom.Metadata.Name, cdrom)
		}
		log.Printf("iSCSI CDROM watcher: synced %d CDROMs", len(list.Items))
		sseBroadcast("imagesUpdated")
	}
	fetchAndSync()

	// Periodic refresh
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fetchAndSync()
			}
		}
	}()

	// Watch with reconnect
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watchISCSICdromStream(ctx, mkubeURL)

		log.Printf("iSCSI CDROM watcher: watch disconnected, will reconnect in 5s")
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			fetchAndSync()
		}
	}
}

func watchISCSICdromStream(ctx context.Context, mkubeURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", mkubeURL+"/api/v1/iscsi-cdroms?watch=true", nil)
	if err != nil {
		log.Printf("iSCSI CDROM watcher: watch request failed: %v", err)
		return
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		log.Printf("iSCSI CDROM watcher: watch connect failed: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("iSCSI CDROM watcher: watch connected")

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event iscsiCdromWatchEvent
		if err := json.Unmarshal(line, &event); err != nil {
			log.Printf("iSCSI CDROM watcher: decode event failed: %v", err)
			continue
		}

		switch event.Type {
		case "ADDED", "MODIFIED":
			iscsiCdromMap.Store(event.Object.Metadata.Name, event.Object)
			log.Printf("iSCSI CDROM watcher: %s %s (iqn=%s)", event.Type, event.Object.Metadata.Name, event.Object.Status.TargetIQN)
			sseBroadcast("imagesUpdated")
		case "DELETED":
			iscsiCdromMap.Delete(event.Object.Metadata.Name)
			log.Printf("iSCSI CDROM watcher: DELETED %s", event.Object.Metadata.Name)
			sseBroadcast("imagesUpdated")
		}
	}
}

// updateBMHImage patches the BMH spec.image in mkube
func updateBMHImage(hostname, image string) error {
	if activeMkubeURL == "" {
		return fmt.Errorf("mkube URL not configured")
	}
	val, ok := bmhMap.Load(hostname)
	if !ok {
		return fmt.Errorf("BMH not found for %s", hostname)
	}
	bmh := val.(bmhObject)
	ns := bmh.Metadata.Namespace
	if ns == "" {
		return fmt.Errorf("BMH %s has no namespace", hostname)
	}

	patch := fmt.Sprintf(`{"spec":{"image":%q}}`, image)
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/baremetalhosts/%s", activeMkubeURL, ns, hostname)
	req, err := http.NewRequest("PATCH", url, strings.NewReader(patch))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PATCH failed (%d): %s", resp.StatusCode, string(body))
	}

	// Update local cache
	bmh.Spec.Image = image
	bmhMap.Store(hostname, bmh)
	log.Printf("BMH image: updated %s/%s image=%s", ns, hostname, image)
	return nil
}

// updateBMHBootConfig patches the BMH spec.bootConfigRef in mkube
func updateBMHBootConfig(hostname, configRef string) error {
	if activeMkubeURL == "" {
		return fmt.Errorf("mkube URL not configured")
	}
	val, ok := bmhMap.Load(hostname)
	if !ok {
		return fmt.Errorf("BMH not found for %s", hostname)
	}
	bmh := val.(bmhObject)
	ns := bmh.Metadata.Namespace
	if ns == "" {
		return fmt.Errorf("BMH %s has no namespace", hostname)
	}

	patch := fmt.Sprintf(`{"spec":{"bootConfigRef":%q}}`, configRef)
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/baremetalhosts/%s", activeMkubeURL, ns, hostname)
	req, err := http.NewRequest("PATCH", url, strings.NewReader(patch))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PATCH failed (%d): %s", resp.StatusCode, string(body))
	}

	// Update local cache
	bmh.Spec.BootConfigRef = configRef
	bmhMap.Store(hostname, bmh)
	log.Printf("BMH bootConfig: updated %s/%s bootConfigRef=%s", ns, hostname, configRef)
	return nil
}

func main() {
	// Initialize database
	if err := initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Parse templates
	var err error
	templates, err = template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	// Ensure PXE boot files exist in /tftpboot
	ensureBootFiles()

	// Start workflow processor
	go workflowProcessor()

	// Start BMH watcher
	mkubeURL := os.Getenv("MKUBE_URL")
	if mkubeURL == "" {
		mkubeURL = DefaultMkubeURL
	}
	activeMkubeURL = mkubeURL
	go bmhWatcher(context.Background(), mkubeURL)
	go iscsiCdromWatcher(context.Background(), mkubeURL)
	go ipmiPowerPoller()

	// Routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/ipxe", handleIPXE)
	http.HandleFunc("/boot.ipxe", handleBootIPXE)

	// Serve boot files via HTTP (faster than TFTP)
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir("/tftpboot"))))

	// API routes
	http.HandleFunc("/api/hosts", handleAPIHosts)
	http.HandleFunc("/api/host", handleAPIHostAction)
	http.HandleFunc("/api/images", handleAPIImages)
	http.HandleFunc("/api/image/update", handleAPIImageUpdate)
	http.HandleFunc("/api/image/delete", handleAPIImageDelete)
	http.HandleFunc("/api/image/add", handleAPIImageAdd)
	http.HandleFunc("/api/logs", handleAPILogs)
	http.HandleFunc("/api/cycle/preset", handleAPICyclePreset)

	// IPMI routes
	http.HandleFunc("/api/host/ipmi", handleAPIHostIPMI)
	http.HandleFunc("/api/host/ipmi/status", handleAPIHostIPMIStatus)
	http.HandleFunc("/api/host/ipmi/test", handleAPIHostIPMITest)
	http.HandleFunc("/api/host/ipmi/config", handleAPIHostIPMIConfig)
	http.HandleFunc("/api/host/config", handleAPIHostConfig)
	http.HandleFunc("/api/hosts/auto-configure", handleAPIHostsAutoConfigure)
	http.HandleFunc("/api/hosts/lookup-hostnames", handleAPIHostsLookupHostnames)

	// Console routes
	http.HandleFunc("/api/host/console/rotate", handleAPIHostConsoleRotate)

	// ISO image routes
	http.HandleFunc("/api/image/iso", handleAPIImageISO)

	// Baremetalservices routes
	http.HandleFunc("/api/host/baremetal/reset-ipmi", handleAPIBaremetalIPMIReset)
	http.HandleFunc("/api/host/baremetal/get-macs", handleAPIBaremetalGetMACs)
	http.HandleFunc("/api/host/baremetal/auto-discover", handleAPIBaremetalAutoDiscover)

	// Workflow routes
	http.HandleFunc("/api/workflows", handleAPIWorkflows)
	http.HandleFunc("/api/workflow/cancel", handleAPIWorkflowCancel)

	// Asset data routes
	http.HandleFunc("/api/asset", handleAPIAssetData)

	// Interface routes
	http.HandleFunc("/api/host/interfaces", handleAPIHostInterfaces)
	http.HandleFunc("/api/host/interface", handleAPIHostInterface)

	// Activity log routes
	http.HandleFunc("/api/activity", handleAPIActivity)

	// SSE event stream
	http.HandleFunc("/events", handleSSE)

	// Redfish API routes (for OpenShift Bare Metal Operator)
	http.HandleFunc("/redfish/v1", handleRedfishRoot)
	http.HandleFunc("/redfish/v1/", handleRedfishRoot)
	http.HandleFunc("/redfish/v1/Systems", handleRedfishSystems)
	http.HandleFunc("/redfish/v1/Systems/", handleRedfishSystemRouter)

	// HTMX partial routes
	http.HandleFunc("/partials/hosts", handleHostsTable)
	http.HandleFunc("/partials/images", handleImagesTable)
	http.HandleFunc("/partials/ipmi", handleIPMITable)
	http.HandleFunc("/partials/logs", handleLogsTable)
	http.HandleFunc("/partials/activity", handleActivityTable)
	http.HandleFunc("/partials/host-detail", handleHostDetail)

	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}

	log.Printf("PXE Manager starting on :%s", port)
	log.Printf("iPXE endpoint: http://localhost:%s/ipxe?mac=XX:XX:XX:XX:XX:XX", port)

	server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
