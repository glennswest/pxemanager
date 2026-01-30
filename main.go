package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bougou/go-ipmi"
	_ "modernc.org/sqlite"
)

const ConsoleServerURL = "http://console.g11.lo"

// Version is set at build time via -ldflags
var Version = "dev"

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

	CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);
	CREATE INDEX IF NOT EXISTS idx_boot_logs_mac ON boot_logs(mac);
	CREATE INDEX IF NOT EXISTS idx_boot_logs_timestamp ON boot_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_workflows_mac ON workflows(mac);
	CREATE INDEX IF NOT EXISTS idx_workflows_state ON workflows(state);
	CREATE INDEX IF NOT EXISTS idx_asset_data_mac ON asset_data(mac);
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
	}
	for _, stmt := range alterStatements {
		db.Exec(stmt) // Ignore errors (column may already exist)
	}

	// Insert default images if not exist
	defaultImages := []Image{
		{Name: "baremetalservices", Kernel: "vmlinuz", Initrd: "initramfs", Append: "vga=normal console=tty0 console=ttyS1,115200n8 ip=dhcp iomem=relaxed", Type: "linux"},
		{Name: "localboot", Kernel: "", Initrd: "", Append: "", Type: "local"},
	}

	for _, img := range defaultImages {
		_, err = db.Exec(`INSERT OR IGNORE INTO images (name, kernel, initrd, append, type) VALUES (?, ?, ?, ?, ?)`,
			img.Name, img.Kernel, img.Initrd, img.Append, img.Type)
		if err != nil {
			log.Printf("Warning: failed to insert default image %s: %v", img.Name, err)
		}
	}

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

	_, err = client.ChassisControl(context.Background(), ipmi.ChassisControlPowerUp)
	if err == nil {
		logActivity("info", "ipmi", host, "Power on command sent")
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
	}
	return err
}

func ipmiRestart(host *Host) error {
	client, err := getIPMIClient(host)
	if err != nil {
		return err
	}
	defer client.Close(context.Background())

	_, err = client.ChassisControl(context.Background(), ipmi.ChassisControlPowerCycle)
	if err == nil {
		logActivity("info", "ipmi", host, "Power cycle command sent")
	}
	return err
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

// Console server integration
func rotateConsoleLogs(hostname, label string) error {
	url := fmt.Sprintf("%s/api/servers/%s/logs/rotate?name=%s",
		ConsoleServerURL, hostname, url.QueryEscape(label))
	resp, err := http.Post(url, "application/json", nil)
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
chain http://192.168.10.200:8080/ipxe?mac=${net0/mac} || shell
`)
}

// iPXE boot script handler
func handleIPXE(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC address required", http.StatusBadRequest)
		return
	}

	// Get or create host
	var host Host
	var hostname, nextImage, cycleImages, lastBoot sql.NullString
	err := db.QueryRow(`SELECT id, mac, hostname, current_image, next_image, cycle_images, cycle_index, last_boot, boot_count FROM hosts WHERE mac = ?`, mac).
		Scan(&host.ID, &host.MAC, &hostname, &host.CurrentImage, &nextImage, &cycleImages, &host.CycleIndex, &lastBoot, &host.BootCount)

	if err == sql.ErrNoRows {
		// Auto-register new host
		_, err = db.Exec(`INSERT INTO hosts (mac, current_image) VALUES (?, 'baremetalservices')`, mac)
		if err != nil {
			log.Printf("Failed to auto-register host %s: %v", mac, err)
		}
		host.MAC = mac
		host.CurrentImage = "baremetalservices"
	} else if err != nil {
		log.Printf("Database error for MAC %s: %v", mac, err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	} else {
		if hostname.Valid {
			host.Hostname = hostname.String
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

	// Determine which image to boot
	imageName := host.CurrentImage

	// Check for next_image (one-shot override)
	if host.NextImage != nil && *host.NextImage != "" {
		imageName = *host.NextImage
		// Clear next_image after use
		db.Exec(`UPDATE hosts SET next_image = NULL WHERE mac = ?`, mac)
	} else if host.CycleImages != nil && *host.CycleImages != "" {
		// Check for boot cycle
		var cycle []string
		if err := json.Unmarshal([]byte(*host.CycleImages), &cycle); err == nil && len(cycle) > 0 {
			if host.CycleIndex < len(cycle) {
				imageName = cycle[host.CycleIndex]
				// Advance cycle index
				newIndex := host.CycleIndex + 1
				if newIndex >= len(cycle) {
					// Cycle complete, clear it
					db.Exec(`UPDATE hosts SET cycle_images = NULL, cycle_index = 0 WHERE mac = ?`, mac)
				} else {
					db.Exec(`UPDATE hosts SET cycle_index = ? WHERE mac = ?`, newIndex, mac)
				}
			}
		}
	}

	// Get image details
	var img Image
	var initrd, appendStr sql.NullString
	err = db.QueryRow(`SELECT name, kernel, initrd, append, type, erase_boot_drive, erase_all_drives, boot_local_after FROM images WHERE name = ?`, imageName).
		Scan(&img.Name, &img.Kernel, &initrd, &appendStr, &img.Type, &img.EraseBootDrive, &img.EraseAllDrives, &img.BootLocalAfter)
	if err != nil {
		log.Printf("Image %s not found, falling back to baremetalservices", imageName)
		imageName = "baremetalservices"
		db.QueryRow(`SELECT name, kernel, initrd, append, type, erase_boot_drive, erase_all_drives, boot_local_after FROM images WHERE name = ?`, imageName).
			Scan(&img.Name, &img.Kernel, &initrd, &appendStr, &img.Type, &img.EraseBootDrive, &img.EraseAllDrives, &img.BootLocalAfter)
	}
	if initrd.Valid {
		img.Initrd = initrd.String
	}
	if appendStr.Valid {
		img.Append = appendStr.String
	}

	// Get full host info for IPMI operations
	fullHost, _ := getHostByMAC(mac)

	// Boot-local-after: set IPMI to boot from disk after this image boots
	if img.BootLocalAfter && fullHost != nil && fullHost.IPMIIP != nil && *fullHost.IPMIIP != "" {
		go func() {
			if err := ipmiSetBootDisk(fullHost); err != nil {
				logActivity("warn", "ipmi", fullHost, fmt.Sprintf("Failed to set boot device to disk: %v", err))
			}
		}()
	}

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
	db.Exec(`UPDATE hosts SET last_boot = CURRENT_TIMESTAMP, boot_count = boot_count + 1 WHERE mac = ?`, mac)

	// Log boot event
	db.Exec(`INSERT INTO boot_logs (mac, hostname, image) VALUES (?, ?, ?)`, mac, host.Hostname, imageName)

	// Log to activity log
	logActivity("info", "boot", fullHost, fmt.Sprintf("Booting image %s", imageName))

	log.Printf("iPXE boot: MAC=%s hostname=%s image=%s", mac, host.Hostname, imageName)

	// Generate iPXE script
	w.Header().Set("Content-Type", "text/plain")

	if img.Type == "local" {
		fmt.Fprintf(w, "#!ipxe\nexit\n")
		return
	}

	httpBase := "http://192.168.10.200:8080/files/"

	script := "#!ipxe\n"
	script += fmt.Sprintf("echo Booting %s for %s (%s)\n", imageName, host.Hostname, mac)

	if img.Type == "memdisk" {
		// For memdisk, args go on kernel line
		script += fmt.Sprintf("kernel %s%s", httpBase, img.Kernel)
		if img.Append != "" {
			script += " " + img.Append
		}
		script += "\n"
		script += fmt.Sprintf("initrd %s%s\n", httpBase, img.Initrd)
	} else {
		script += fmt.Sprintf("kernel %s%s", httpBase, img.Kernel)
		if img.Append != "" {
			script += " " + img.Append
		}
		script += "\n"
		if img.Initrd != "" {
			script += fmt.Sprintf("initrd %s%s\n", httpBase, img.Initrd)
		}
	}
	script += "boot\n"

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

	switch action {
	case "set_image":
		image := r.FormValue("image")
		if image == "" {
			http.Error(w, "image required", http.StatusBadRequest)
			return
		}

		// Check if image has erase flags - if so, create a workflow
		var eraseBootDrive, eraseAllDrives bool
		db.QueryRow(`SELECT erase_boot_drive, erase_all_drives FROM images WHERE name = ?`, image).
			Scan(&eraseBootDrive, &eraseAllDrives)

		if eraseBootDrive || eraseAllDrives {
			// Create erase workflow - this will boot to baremetalservices first, erase, then boot target
			if err := createEraseWorkflow(mac, image, eraseBootDrive, eraseAllDrives); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Set current image to the target (workflow will handle the erase step)
			_, err := db.Exec(`UPDATE hosts SET current_image = ? WHERE mac = ?`, image, mac)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// No erase needed, just set the image directly
			_, err := db.Exec(`UPDATE hosts SET current_image = ? WHERE mac = ?`, image, mac)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

	case "set_next":
		image := r.FormValue("image")
		_, err := db.Exec(`UPDATE hosts SET next_image = ? WHERE mac = ?`, image, mac)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case "set_cycle":
		cycleJSON := r.FormValue("cycle")
		_, err := db.Exec(`UPDATE hosts SET cycle_images = ?, cycle_index = 0 WHERE mac = ?`, cycleJSON, mac)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case "clear_cycle":
		_, err := db.Exec(`UPDATE hosts SET cycle_images = NULL, cycle_index = 0, next_image = NULL WHERE mac = ?`, mac)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
		return
	}

	action := r.URL.Query().Get("action")
	host, err := getHostByMAC(mac)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	if host.IPMIIP == nil || *host.IPMIIP == "" {
		http.Error(w, "IPMI not configured for this host", http.StatusBadRequest)
		return
	}

	switch action {
	case "restart":
		if err := ipmiRestart(host); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "power_on":
		if err := ipmiPowerOn(host); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "power_off":
		if err := ipmiPowerOff(host); err != nil {
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

	w.Header().Set("HX-Trigger", "hostsUpdated")
	w.WriteHeader(http.StatusOK)
}

func handleAPIHostIPMIStatus(w http.ResponseWriter, r *http.Request) {
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

	if host.IPMIIP == nil || *host.IPMIIP == "" {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "-")
		return
	}

	status, _ := ipmiPowerStatus(host)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, status)
}

func handleAPIHostIPMITest(w http.ResponseWriter, r *http.Request) {
	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
		return
	}

	host, err := getHostByMAC(mac)
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

	mac := normalizeMAC(r.URL.Query().Get("mac"))
	if mac == "" {
		http.Error(w, "MAC required", http.StatusBadRequest)
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

	_, err := db.Exec(`UPDATE hosts SET ipmi_ip = ?, ipmi_username = ?, ipmi_password = ? WHERE mac = ?`,
		ipmiIP, ipmiUsername, ipmiPassword, mac)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	host, _ := getHostByMAC(mac)
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

// lookupHostnameByMAC tries to find hostname via DNS/ARP
func lookupHostnameByMAC(mac string) string {
	// Try to find IP from ARP table or DHCP leases
	// This is a simplified approach - check /var/lib/misc/dnsmasq.leases if available
	leaseFile := "/var/lib/misc/dnsmasq.leases"
	data, err := os.ReadFile(leaseFile)
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 4 && strings.EqualFold(fields[1], mac) {
				// Found MAC, fields[2] is IP, fields[3] is hostname
				if len(fields) >= 4 && fields[3] != "*" {
					return fields[3]
				}
				// Try reverse DNS on the IP
				if len(fields) >= 3 {
					names, err := net.LookupAddr(fields[2])
					if err == nil && len(names) > 0 {
						hostname := strings.TrimSuffix(names[0], ".")
						// Remove domain suffix if present
						if idx := strings.Index(hostname, "."); idx > 0 {
							return hostname[:idx]
						}
						return hostname
					}
				}
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
			// Auto-configure IPMI - use short hostname + .g11.lo
			// Strip any existing domain first
			shortName := host.Hostname
			if idx := strings.Index(host.Hostname, "."); idx > 0 {
				shortName = host.Hostname[:idx]
			}
			ipmiIP := shortName + ".g11.lo"
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
	images, _ := getImages()

	data := struct {
		Hosts  []Host
		Images []Image
	}{hosts, images}

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

	assetData, _ := getAssetData(mac) // May be nil if no asset data

	data := struct {
		Host      *Host
		AssetData *AssetData
	}{host, assetData}

	templates.ExecuteTemplate(w, "host_detail.html", data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	hosts, _ := getHosts()
	images, _ := getImages()
	logs, _ := getBootLogs(20)

	data := struct {
		Hosts   []Host
		Images  []Image
		Logs    []BootLog
		Version string
	}{hosts, images, logs, Version}

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

	// Start workflow processor
	go workflowProcessor()

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

	// Workflow routes
	http.HandleFunc("/api/workflows", handleAPIWorkflows)
	http.HandleFunc("/api/workflow/cancel", handleAPIWorkflowCancel)

	// Asset data routes
	http.HandleFunc("/api/asset", handleAPIAssetData)

	// Activity log routes
	http.HandleFunc("/api/activity", handleAPIActivity)

	// HTMX partial routes
	http.HandleFunc("/partials/hosts", handleHostsTable)
	http.HandleFunc("/partials/images", handleImagesTable)
	http.HandleFunc("/partials/ipmi", handleIPMITable)
	http.HandleFunc("/partials/logs", handleLogsTable)
	http.HandleFunc("/partials/activity", handleActivityTable)
	http.HandleFunc("/partials/host-detail", handleHostDetail)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
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
