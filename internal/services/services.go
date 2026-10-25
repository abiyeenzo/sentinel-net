package services

import (
	"fmt"
	"regexp"
	"strings"
)

// StaticEntry describes a known TCP service indexed by default port number.
type StaticEntry struct {
	Port          int
	ID            string
	Label         string
	Category      string
	Encrypted     bool
	TLSCandidate  bool
	HTTPCandidate bool
	Description   string
}

// ServiceInfo describes the resolved service metadata attached to a port observation.
type ServiceInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	Encrypted   bool   `json:"encrypted"`
	Confidence  string `json:"confidence"`
	Product     string `json:"product,omitempty"`
	Description string `json:"description"`
}

// Clues holds optional protocol observations used to refine static port hints.
type Clues struct {
	Banner         string
	TLSEstablished bool
	HTTPStatusCode int
	HTTPServer     string
	HTTPPoweredBy  string
}

var ansiSequenceRE = regexp.MustCompile(`\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))`)

// SanitizeText strips ANSI escape sequences and non-printable control characters
// from untrusted network strings (banners, HTTP headers, certificate fields).
func SanitizeText(raw string, maxLen int) string {
	if raw == "" {
		return ""
	}
	cleaned := ansiSequenceRE.ReplaceAllString(raw, "")
	var b strings.Builder
	b.Grow(len(cleaned))
	lastSpace := false
	for _, r := range cleaned {
		if r < 0x20 || r == 0x7f {
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		if r == ' ' || r == '\t' {
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		b.WriteRune(r)
		lastSpace = false
	}
	out := strings.TrimSpace(b.String())
	if maxLen > 0 && len(out) > maxLen {
		if maxLen <= 3 {
			return out[:maxLen]
		}
		return out[:maxLen-3] + "..."
	}
	return out
}

var registry = map[int]StaticEntry{
	20:    {20, "ftp-data", "FTP Data", "file-sharing", false, false, false, "Canal de donnees FTP non chiffre"},
	21:    {21, "ftp", "FTP", "file-sharing", false, false, false, "Transfert de fichiers FTP en clair"},
	22:    {22, "ssh", "SSH", "remote-access", true, false, false, "Administration distante Secure Shell"},
	23:    {23, "telnet", "Telnet", "remote-access", false, false, false, "Terminal distant Telnet non chiffre"},
	25:    {25, "smtp", "SMTP", "mail", false, false, false, "Relais de messagerie SMTP"},
	53:    {53, "domain", "DNS", "network", false, false, false, "Service DNS sur TCP"},
	69:    {69, "tftp", "TFTP", "file-sharing", false, false, false, "Transfert de fichiers TFTP sans authentification"},
	79:    {79, "finger", "Finger", "directory", false, false, false, "Service Finger historique"},
	80:    {80, "http", "HTTP", "web", false, false, true, "Serveur Web HTTP non chiffre"},
	81:    {81, "http-alt", "HTTP Alt", "web", false, false, true, "Serveur Web HTTP secondaire"},
	88:    {88, "kerberos", "Kerberos", "directory", true, false, false, "Authentification Kerberos / Active Directory"},
	110:   {110, "pop3", "POP3", "mail", false, false, false, "Messagerie POP3 en clair"},
	111:   {111, "rpcbind", "RPCBind", "network", false, false, false, " Portmapper ONC RPC"},
	119:   {119, "nntp", "NNTP", "messaging", false, false, false, "Serveur Usenet NNTP"},
	135:   {135, "msrpc", "MSRPC", "network", false, false, false, "Endpoint Mapper RPC Windows"},
	139:   {139, "netbios-ssn", "NetBIOS", "file-sharing", false, false, false, "Session NetBIOS sur TCP"},
	143:   {143, "imap", "IMAP", "mail", false, false, false, "Messagerie IMAP en clair"},
	161:   {161, "snmp", "SNMP", "monitoring", false, false, false, "Supervision reseau SNMP"},
	179:   {179, "bgp", "BGP", "network", false, false, false, "Routage inter-domaine BGP"},
	389:   {389, "ldap", "LDAP", "directory", false, false, false, "Annuaire LDAP sans TLS implicite"},
	443:   {443, "https", "HTTPS", "web", true, true, true, "Serveur Web HTTP sur TLS"},
	445:   {445, "microsoft-ds", "SMB", "file-sharing", false, false, false, "Partage de fichiers Windows SMB"},
	464:   {464, "kpasswd5", "Kerberos Passwd", "directory", true, false, false, "Gestion de mot de passe Kerberos"},
	465:   {465, "smtps", "SMTPS", "mail", true, true, false, "Soumission SMTP sur TLS"},
	502:   {502, "modbus", "Modbus TCP", "industrial", false, false, false, "Protocole automate industriel Modbus"},
	512:   {512, "exec", "rexec", "remote-access", false, false, false, "Execution distante BSD rexec"},
	513:   {513, "login", "rlogin", "remote-access", false, false, false, "Connexion distante BSD rlogin"},
	514:   {514, "shell", "rsh / Syslog", "remote-access", false, false, false, "Remote Shell BSD ou collecte Syslog TCP"},
	515:   {515, "printer", "LPD", "network", false, false, false, "Service d'impression LPD"},
	548:   {548, "afp", "AFP", "file-sharing", false, false, false, "Partage Apple Filing Protocol"},
	554:   {554, "rtsp", "RTSP", "iot", false, false, false, "Flux video RTSP"},
	587:   {587, "submission", "SMTP Submission", "mail", false, false, false, "Soumission SMTP (STARTTLS attendu)"},
	593:   {593, "http-rpc-epmap", "RPC over HTTP", "network", false, false, false, "Microsoft RPC sur HTTP"},
	623:   {623, "ipmi", "IPMI / BMC", "remote-access", false, false, false, "Administration hors-bande IPMI"},
	631:   {631, "ipp", "IPP / CUPS", "network", false, false, true, "Serveur d'impression IPP"},
	636:   {636, "ldaps", "LDAPS", "directory", true, true, false, "Annuaire LDAP sur TLS"},
	873:   {873, "rsync", "rsync", "backup", false, false, false, "Synchronisation de fichiers rsync"},
	902:   {902, "vmware-auth", "VMware Auth", "remote-access", true, true, false, "Console hyperviseur VMware ESXi"},
	990:   {990, "ftps", "FTPS", "file-sharing", true, true, false, "Transfert FTP sur TLS"},
	993:   {993, "imaps", "IMAPS", "mail", true, true, false, "Messagerie IMAP sur TLS"},
	995:   {995, "pop3s", "POP3S", "mail", true, true, false, "Messagerie POP3 sur TLS"},
	1080:  {1080, "socks", "SOCKS Proxy", "proxy", false, false, false, "Mandataire reseau SOCKS"},
	1099:  {1099, "rmiregistry", "Java RMI", "network", false, false, false, "Registre Java RMI"},
	1433:  {1433, "ms-sql-s", "MSSQL", "database", false, false, false, "Microsoft SQL Server"},
	1434:  {1434, "ms-sql-m", "MSSQL Monitor", "database", false, false, false, "SQL Server Browser"},
	1521:  {1521, "oracle", "Oracle TNS", "database", false, false, false, "Listener Oracle Database"},
	1723:  {1723, "pptp", "PPTP", "network", false, false, false, "Tunnel VPN PPTP historique"},
	1883:  {1883, "mqtt", "MQTT", "iot", false, false, false, "Broker IoT MQTT non chiffre"},
	2049:  {2049, "nfs", "NFS", "file-sharing", false, false, false, "Partage Network File System"},
	2181:  {2181, "zookeeper", "ZooKeeper", "containers", false, false, false, "Coordination Apache ZooKeeper"},
	2222:  {2222, "ssh-alt", "SSH Alt", "remote-access", true, false, false, "Port SSH secondaire"},
	2323:  {2323, "telnet-alt", "Telnet Alt", "remote-access", false, false, false, "Port Telnet secondaire IoT"},
	2375:  {2375, "docker", "Docker API", "containers", false, false, true, "API Docker Engine non chiffree"},
	2376:  {2376, "docker-tls", "Docker TLS", "containers", true, true, true, "API Docker Engine sur TLS"},
	2377:  {2377, "docker-swarm", "Docker Swarm", "containers", true, true, false, "Cluster Docker Swarm"},
	2379:  {2379, "etcd-client", "etcd Client", "containers", false, false, true, "Magasin cle-valeur etcd"},
	2380:  {2380, "etcd-peer", "etcd Peer", "containers", false, false, false, "Communication inter-noeuds etcd"},
	3000:  {3000, "http-app", "HTTP App (3000)", "web", false, false, true, "Application Web Node.js ou Grafana"},
	3001:  {3001, "http-alt-3001", "HTTP App (3001)", "web", false, false, true, "Service Web applicatif secondaire"},
	3128:  {3128, "squid-http", "HTTP Proxy", "proxy", false, false, true, "Mandataire HTTP Squid"},
	3260:  {3260, "iscsi", "iSCSI", "file-sharing", false, false, false, "Stockage reseau bloc iSCSI"},
	3268:  {3268, "msft-gc", "AD Global Catalog", "directory", false, false, false, "Catalogue global Active Directory"},
	3269:  {3269, "msft-gc-ssl", "AD GC SSL", "directory", true, true, false, "Catalogue global AD sur TLS"},
	3306:  {3306, "mysql", "MySQL / MariaDB", "database", false, false, false, "Base de donnees MySQL ou MariaDB"},
	33060: {33060, "mysqlx", "MySQL X", "database", false, false, false, "Protocole MySQL X"},
	3389:  {3389, "ms-wbt-server", "RDP", "remote-access", true, true, false, "Bureau a distance Windows RDP"},
	3690:  {3690, "svn", "Subversion", "network", false, false, false, "Serveur Subversion"},
	4000:  {4000, "http-4000", "HTTP Service (4000)", "web", false, false, true, "Serveur applicatif HTTP"},
	4200:  {4200, "http-4200", "HTTP Dev (4200)", "web", false, false, true, "Serveur Web applicatif"},
	4243:  {4243, "docker-alt", "Docker API Alt", "containers", false, false, true, "Port alternatif API Docker"},
	4369:  {4369, "epmd", "Erlang EPMD", "messaging", false, false, false, "Erlang Port Mapper Daemon"},
	4840:  {4840, "opcua", "OPC-UA", "industrial", false, false, false, "Protocole industriel OPC-UA"},
	4848:  {4848, "glassfish", "GlassFish Admin", "web", false, false, true, "Console d'administration GlassFish"},
	5000:  {5000, "http-5000", "HTTP / Registry", "web", false, false, true, "API HTTP ou Docker Registry"},
	5001:  {5001, "https-5001", "HTTPS Admin (5001)", "web", true, true, true, "Console HTTPS d'administration"},
	5060:  {5060, "sip", "SIP", "messaging", false, false, false, "Signalisation VoIP SIP en clair"},
	5061:  {5061, "sips", "SIP TLS", "messaging", true, true, false, "Signalisation VoIP SIP sur TLS"},
	5173:  {5173, "vite-dev", "Frontend Dev (5173)", "web", false, false, true, "Serveur de developpement frontend"},
	5432:  {5432, "postgresql", "PostgreSQL", "database", false, false, false, "Base de donnees PostgreSQL"},
	5601:  {5601, "kibana", "Kibana", "monitoring", false, false, true, "Console Elastic Kibana"},
	5672:  {5672, "amqp", "AMQP / RabbitMQ", "messaging", false, false, false, "Courtier de messages AMQP"},
	5683:  {5683, "coap", "CoAP", "iot", false, false, false, "Protocole IoT CoAP"},
	5900:  {5900, "vnc", "VNC", "remote-access", false, false, false, "Controle graphique distant VNC"},
	5901:  {5901, "vnc-1", "VNC :1", "remote-access", false, false, false, "Session VNC secondaire"},
	5984:  {5984, "couchdb", "CouchDB", "database", false, false, true, "Base de donnees Apache CouchDB"},
	5985:  {5985, "wsman", "WinRM HTTP", "remote-access", false, false, true, "Windows Remote Management HTTP"},
	5986:  {5986, "wsmans", "WinRM HTTPS", "remote-access", true, true, true, "Windows Remote Management HTTPS"},
	6379:  {6379, "redis", "Redis", "database", false, false, false, "Magasin en memoire Redis"},
	6380:  {6380, "redis-tls", "Redis TLS", "database", true, true, false, "Instance Redis sur TLS"},
	6443:  {6443, "kubernetes-api", "Kubernetes API", "containers", true, true, true, "API Server Kubernetes"},
	7000:  {7000, "cassandra-inter", "Cassandra / HTTP", "database", false, false, true, "Cluster Cassandra ou service HTTP"},
	7001:  {7001, "weblogic", "WebLogic", "web", false, false, true, "Serveur Oracle WebLogic"},
	7474:  {7474, "neo4j", "Neo4j HTTP", "database", false, false, true, "Base orientee graphe Neo4j"},
	7547:  {7547, "cwmp", "TR-069", "iot", false, false, true, "Gestion distante routeur CPE TR-069"},
	8000:  {8000, "http-8000", "HTTP (8000)", "web", false, false, true, "Serveur HTTP applicatif"},
	8001:  {8001, "http-8001", "HTTP / K8s Proxy", "containers", false, false, true, "Proxy Kubernetes ou API HTTP"},
	8006:  {8006, "proxmox", "Proxmox VE", "remote-access", true, true, true, "Interface d'administration Proxmox"},
	8008:  {8008, "http-8008", "HTTP (8008)", "web", false, false, true, "Serveur HTTP alternatif"},
	8009:  {8009, "ajp13", "Apache AJP", "web", false, false, false, "Connecteur binaire Apache AJP"},
	8080:  {8080, "http-proxy", "HTTP Alt (8080)", "web", false, false, true, "Serveur Web, proxy ou console d'administration"},
	8081:  {8081, "http-8081", "HTTP Admin (8081)", "web", false, false, true, "Interface HTTP secondaire"},
	8086:  {8086, "influxdb", "InfluxDB", "database", false, false, true, "Base series temporelles InfluxDB"},
	8088:  {8088, "http-8088", "HTTP (8088)", "web", false, false, true, "Service Web applicatif"},
	8123:  {8123, "clickhouse-http", "ClickHouse / HTTP", "database", false, false, true, "Interface HTTP ClickHouse ou domotique"},
	8200:  {8200, "vault", "HashiCorp Vault", "directory", false, false, true, "Gestionnaire de secrets Vault"},
	8443:  {8443, "https-alt", "HTTPS Alt (8443)", "web", true, true, true, "Console ou service HTTPS secondaire"},
	8500:  {8500, "consul", "HashiCorp Consul", "containers", false, false, true, "API HTTP HashiCorp Consul"},
	8883:  {8883, "secure-mqtt", "MQTT TLS", "iot", true, true, false, "Broker IoT MQTT sur TLS"},
	8888:  {8888, "http-8888", "Jupyter / HTTP", "web", false, false, true, "Notebook Jupyter ou service Web"},
	9000:  {9000, "http-9000", "MinIO / SonarQube / FPM", "web", false, false, true, "Service applicatif sur port 9000"},
	9001:  {9001, "http-9001", "MinIO Console", "web", false, false, true, "Console d'administration Web"},
	9042:  {9042, "cassandra", "Cassandra CQL", "database", false, false, false, "Protocole natif Apache Cassandra"},
	9090:  {9090, "prometheus", "Prometheus / Cockpit", "monitoring", false, false, true, "Serveur Prometheus ou console Cockpit"},
	9092:  {9092, "kafka", "Apache Kafka", "messaging", false, false, false, "Broker Apache Kafka"},
	9093:  {9093, "alertmanager", "Alertmanager", "monitoring", false, false, true, "Prometheus Alertmanager"},
	9100:  {9100, "node-exporter", "Node Exporter / JetDirect", "monitoring", false, false, true, "Exporteur de metriques ou impression RAW"},
	9200:  {9200, "elasticsearch", "Elasticsearch HTTP", "database", false, false, true, "API REST Elasticsearch"},
	9300:  {9300, "elasticsearch-tcp", "Elasticsearch Transport", "database", false, false, false, "Transport inter-noeuds Elasticsearch"},
	9418:  {9418, "git", "Git Daemon", "file-sharing", false, false, false, "Protocole git:// non chiffre"},
	9443:  {9443, "https-9443", "HTTPS Admin (9443)", "web", true, true, true, "Console HTTPS d'administration"},
	10000: {10000, "webmin", "Webmin", "remote-access", false, false, true, "Administration systeme Webmin"},
	10250: {10250, "kubelet", "Kubelet API", "containers", true, true, true, "API agent Kubernetes Kubelet"},
	10255: {10255, "kubelet-ro", "Kubelet Read-Only", "containers", false, false, true, "Port Kubelet en lecture seule non authentifie"},
	11211: {11211, "memcached", "Memcached", "database", false, false, false, "Cache distribue Memcached"},
	15672: {15672, "rabbitmq-mgmt", "RabbitMQ Mgmt", "messaging", false, false, true, "Console HTTP RabbitMQ"},
	27017: {27017, "mongodb", "MongoDB", "database", false, false, false, "Base NoSQL MongoDB"},
	28017: {28017, "mongodb-http", "MongoDB HTTP", "database", false, false, true, "Interface HTTP de statut MongoDB"},
	47808: {47808, "bacnet", "BACnet", "industrial", false, false, false, "Protocole immotique BACnet"},
}

type bannerSig struct {
	re        *regexp.Regexp
	id        string
	label     string
	category  string
	encrypted bool
}

var bannerSignatures = []bannerSig{
	{regexp.MustCompile(`(?i)^SSH-\d+\.\d+-([^\s]+)`), "ssh", "SSH", "remote-access", true},
	{regexp.MustCompile(`(?i)^220[- ].*(ESMTP|SMTP|Postfix|Exim|Sendmail)`), "smtp", "SMTP", "mail", false},
	{regexp.MustCompile(`(?i)^220[- ].*(FTP|vsFTPd|ProFTPD|Pure-FTPd|FileZilla)`), "ftp", "FTP", "file-sharing", false},
	{regexp.MustCompile(`(?i)^\+OK\b`), "pop3", "POP3", "mail", false},
	{regexp.MustCompile(`(?i)^\* OK\b.*IMAP`), "imap", "IMAP", "mail", false},
	{regexp.MustCompile(`(?i)^-ERR\b.*redis|^\$|^REDIS`), "redis", "Redis", "database", false},
	{regexp.MustCompile(`(?i)mysql_native_password|caching_sha2_password|MariaDB`), "mysql", "MySQL / MariaDB", "database", false},
	{regexp.MustCompile(`(?i)^RFB \d{3}\.\d{3}`), "vnc", "VNC", "remote-access", false},
	{regexp.MustCompile(`(?i)^HTTP/1\.[01]\s+\d{3}`), "http", "HTTP", "web", false},
}

// LookupPort returns the static metadata entry for a TCP port.
func LookupPort(port int) (StaticEntry, bool) {
	if e, ok := registry[port]; ok {
		return e, true
	}
	return StaticEntry{
		Port:          port,
		ID:            "unknown-tcp",
		Label:         fmt.Sprintf("TCP/%d", port),
		Category:      "custom",
		Encrypted:     false,
		TLSCandidate:  port == 443 || port == 8443 || port == 9443,
		HTTPCandidate: false,
		Description:   "Port TCP non standard ou applicatif personnalise",
	}, false
}

// Identify combines static port definitions with passive protocol clues.
func Identify(port int, clues *Clues) ServiceInfo {
	base, known := LookupPort(port)
	info := ServiceInfo{
		ID:          base.ID,
		Label:       base.Label,
		Category:    base.Category,
		Encrypted:   base.Encrypted,
		Confidence:  "unclassified",
		Description: strings.TrimSpace(base.Description),
	}
	if known {
		info.Confidence = "port-hint"
	}
	if clues == nil {
		return info
	}

	if clues.TLSEstablished {
		info.Encrypted = true
		info.Confidence = "protocol-verified"
		if info.ID == "http" || info.ID == "unknown-tcp" {
			if clues.HTTPStatusCode > 0 {
				info.ID = "https"
				info.Label = "HTTPS"
				info.Category = "web"
			} else if info.ID == "unknown-tcp" {
				info.ID = "tls-service"
				info.Label = fmt.Sprintf("TLS/%d", port)
			}
		}
	}

	if clues.HTTPStatusCode > 0 {
		info.Confidence = "protocol-verified"
		if !clues.TLSEstablished && info.ID == "unknown-tcp" {
			info.ID = "http"
			info.Label = "HTTP"
			info.Category = "web"
		}
		if clues.HTTPServer != "" {
			info.Product = SanitizeText(clues.HTTPServer, 96)
		} else if clues.HTTPPoweredBy != "" {
			info.Product = SanitizeText(clues.HTTPPoweredBy, 96)
		}
	}

	if clues.Banner != "" {
		clean := SanitizeText(clues.Banner, 160)
		for _, sig := range bannerSignatures {
			if sig.re.MatchString(clean) {
				info.ID = sig.id
				info.Label = sig.label
				info.Category = sig.category
				info.Encrypted = info.Encrypted || sig.encrypted
				info.Confidence = "banner-verified"
				if info.Product == "" {
					info.Product = SanitizeText(clean, 96)
				}
				break
			}
		}
		if info.Product == "" && clean != "" {
			info.Product = SanitizeText(clean, 80)
		}
	}

	return info
}
