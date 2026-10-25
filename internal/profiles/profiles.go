package profiles

import (
	"fmt"
	"strings"
)

// Profile defines a named, reusable set of TCP ports for defensive auditing.
type Profile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Ports       []int  `json:"ports"`
}

var top100Ports = []int{
	20, 21, 22, 23, 25, 53, 69, 79, 80, 81,
	88, 110, 111, 119, 135, 139, 143, 161, 179, 389,
	443, 445, 464, 465, 502, 512, 513, 514, 515, 548,
	554, 587, 593, 623, 631, 636, 873, 902, 990, 993,
	995, 1080, 1099, 1433, 1434, 1521, 1723, 1883, 2049, 2181,
	2222, 2323, 2375, 2376, 2379, 3000, 3001, 3128, 3260, 3268,
	3269, 3306, 3389, 3690, 4000, 4200, 4369, 4840, 4848, 5000,
	5001, 5060, 5061, 5432, 5601, 5672, 5900, 5984, 5985, 5986,
	6379, 6443, 7000, 7001, 7474, 7547, 8000, 8006, 8008, 8009,
	8080, 8081, 8086, 8200, 8443, 8500, 8883, 8888, 9000, 9042,
}

var orderedIDs = []string{"quick", "web", "infra", "database", "containers", "iot", "top100"}

var catalog = map[string]Profile{
	"quick": {
		ID:          "quick",
		Name:        "Audit rapide",
		Description: "22 ports courants d'administration, web, fichiers et bases de donnees.",
		Ports:       []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 27017},
	},
	"web": {
		ID:          "web",
		Name:        "Surface Web et API",
		Description: "Ports HTTP/HTTPS standards, proxys inverses, consoles d'administration et serveurs applicatifs.",
		Ports:       []int{80, 81, 443, 3000, 3001, 4000, 4200, 5000, 5001, 5173, 7001, 8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443, 10000},
	},
	"infra": {
		ID:          "infra",
		Name:        "Infrastructure et Active Directory",
		Description: "Annuaires, partage SMB/NFS, RPC, gestion hors-bande IPMI, hyperviseurs et administration.",
		Ports:       []int{21, 22, 23, 25, 53, 88, 111, 135, 139, 161, 389, 445, 464, 514, 623, 636, 873, 902, 2049, 3260, 3268, 3269, 3389, 5900, 5985, 5986, 8006},
	},
	"database": {
		ID:          "database",
		Name:        "Bases de donnees et caches",
		Description: "Moteurs SQL, NoSQL, caches en memoire et moteurs d'indexation.",
		Ports:       []int{1433, 1434, 1521, 3306, 33060, 5432, 5601, 5984, 6379, 6380, 7000, 7474, 8086, 8123, 9042, 9200, 9300, 11211, 27017, 28017},
	},
	"containers": {
		ID:          "containers",
		Name:        "Conteneurs et orchestration",
		Description: "Docker Engine, Kubernetes API, Kubelet, etcd, Consul, Vault et Prometheus.",
		Ports:       []int{2181, 2375, 2376, 2377, 2379, 2380, 4243, 5000, 6443, 8001, 8200, 8500, 9090, 9093, 9100, 10250, 10255},
	},
	"iot": {
		ID:          "iot",
		Name:        "IoT et protocoles industriels",
		Description: "Modbus, OPC-UA, BACnet, MQTT, flux RTSP et administration CPE.",
		Ports:       []int{21, 22, 23, 80, 443, 502, 554, 1883, 2323, 4840, 5683, 7547, 8080, 8883, 47808},
	},
	"top100": {
		ID:          "top100",
		Name:        "Top 100 entreprise",
		Description: "Selection des 100 ports TCP les plus exposes en environnement serveur et cloud.",
		Ports:       top100Ports,
	},
}

// Get returns a copy of the named scan profile.
func Get(name string) (Profile, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if p, ok := catalog[key]; ok {
		ports := make([]int, len(p.Ports))
		copy(ports, p.Ports)
		p.Ports = ports
		return p, nil
	}
	return Profile{}, fmt.Errorf("unknown profile %q (available: %s)", name, strings.Join(orderedIDs, ", "))
}

// All returns all built-in profiles in deterministic order.
func All() []Profile {
	out := make([]Profile, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		p := catalog[id]
		ports := make([]int, len(p.Ports))
		copy(ports, p.Ports)
		p.Ports = ports
		out = append(out, p)
	}
	return out
}
