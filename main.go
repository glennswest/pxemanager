package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed templates/*
var templatesFS embed.FS

var db *sql.DB
var templates *template.Template

// Image represents a bootable image
type Image struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Kernel  string `json:"kernel"`
	Initrd  string `json:"initrd"`
	Append  string `json:"append"`
	Type    string `json:"type"` // linux, memdisk
	Created string `json:"created"`
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
	Created      string  `json:"created"`
}

// BootLog represents a boot event
type BootLog struct {
	ID        int    `json:"id"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	Image     string `json:"image"`
	Timestamp string `json:"timestamp"`
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

	CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);
	CREATE INDEX IF NOT EXISTS idx_boot_logs_mac ON boot_logs(mac);
	CREATE INDEX IF NOT EXISTS idx_boot_logs_timestamp ON boot_logs(timestamp);
	`

	_, err = db.Exec(schema)
	if err != nil {
		return err
	}

	// Insert default images if not exist
	defaultImages := []Image{
		{Name: "baremetalservices", Kernel: "vmlinuz", Initrd: "initramfs", Append: "vga=normal console=tty0 console=ttyS1,115200n8 ip=dhcp iomem=relaxed", Type: "linux"},
		{Name: "biosupdate", Kernel: "memdisk", Initrd: "biosupdate.img", Append: "raw", Type: "memdisk"},
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
	rows, err := db.Query(`SELECT id, name, kernel, initrd, append, type, created FROM images ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var images []Image
	for rows.Next() {
		var img Image
		var initrd, appendStr sql.NullString
		if err := rows.Scan(&img.ID, &img.Name, &img.Kernel, &initrd, &appendStr, &img.Type, &img.Created); err != nil {
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
	rows, err := db.Query(`SELECT id, mac, hostname, current_image, next_image, cycle_images, cycle_index, last_boot, boot_count, created FROM hosts ORDER BY hostname, mac`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var hostname, nextImage, cycleImages, lastBoot sql.NullString
		if err := rows.Scan(&h.ID, &h.MAC, &hostname, &h.CurrentImage, &nextImage, &cycleImages, &h.CycleIndex, &lastBoot, &h.BootCount, &h.Created); err != nil {
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
	err = db.QueryRow(`SELECT name, kernel, initrd, append, type FROM images WHERE name = ?`, imageName).
		Scan(&img.Name, &img.Kernel, &initrd, &appendStr, &img.Type)
	if err != nil {
		log.Printf("Image %s not found, falling back to baremetalservices", imageName)
		imageName = "baremetalservices"
		db.QueryRow(`SELECT name, kernel, initrd, append, type FROM images WHERE name = ?`, imageName).
			Scan(&img.Name, &img.Kernel, &initrd, &appendStr, &img.Type)
	}
	if initrd.Valid {
		img.Initrd = initrd.String
	}
	if appendStr.Valid {
		img.Append = appendStr.String
	}

	// Update boot stats
	db.Exec(`UPDATE hosts SET last_boot = CURRENT_TIMESTAMP, boot_count = boot_count + 1 WHERE mac = ?`, mac)

	// Log boot event
	db.Exec(`INSERT INTO boot_logs (mac, hostname, image) VALUES (?, ?, ?)`, mac, host.Hostname, imageName)

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
		script += fmt.Sprintf("kernel %s%s\n", httpBase, img.Kernel)
		script += fmt.Sprintf("initrd %s%s\n", httpBase, img.Initrd)
		if img.Append != "" {
			script += fmt.Sprintf("imgargs %s %s\n", img.Kernel, img.Append)
		}
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
		_, err := db.Exec(`UPDATE hosts SET current_image = ? WHERE mac = ?`, image, mac)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
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
		_, err := db.Exec(`INSERT INTO images (name, kernel, initrd, append, type) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET kernel = ?, initrd = ?, append = ?, type = ?`,
			img.Name, img.Kernel, img.Initrd, img.Append, img.Type,
			img.Kernel, img.Initrd, img.Append, img.Type)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
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

func handleLogsTable(w http.ResponseWriter, r *http.Request) {
	logs, _ := getBootLogs(50)
	templates.ExecuteTemplate(w, "logs_table.html", logs)
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
		Hosts  []Host
		Images []Image
		Logs   []BootLog
	}{hosts, images, logs}

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
	http.HandleFunc("/api/logs", handleAPILogs)
	http.HandleFunc("/api/cycle/preset", handleAPICyclePreset)

	// HTMX partial routes
	http.HandleFunc("/partials/hosts", handleHostsTable)
	http.HandleFunc("/partials/images", handleImagesTable)
	http.HandleFunc("/partials/logs", handleLogsTable)

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
