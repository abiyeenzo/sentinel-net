package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/abiyeenzo/sentinel-net/internal/inspector"
	"github.com/abiyeenzo/sentinel-net/internal/services"
)

// ReferenceLink points to an official CVE or vendor security advisory.
type ReferenceLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// Component represents a software product and version passively fingerprinted on a port.
type Component struct {
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Display    string `json:"display"`
	Version    string `json:"version"`
	DistroHint string `json:"distroHint,omitempty"`
	CPE        string `json:"cpe"`
	Source     string `json:"source"`
}

// AdvisoryMatch describes a potential CVE affecting an observed service or TLS configuration.
type AdvisoryMatch struct {
	CVE             string          `json:"cve"`
	Title           string          `json:"title"`
	Product         string          `json:"product"`
	DetectedVersion string          `json:"detectedVersion"`
	CPE             string          `json:"cpe,omitempty"`
	AffectedScope   string          `json:"affectedScope"`
	FixedVersion    string          `json:"fixedVersion,omitempty"`
	Severity        string          `json:"severity"`
	CVSS            float64         `json:"cvss"`
	CVSSVector      string          `json:"cvssVector,omitempty"`
	CWE             string          `json:"cwe,omitempty"`
	Confidence      string          `json:"confidence"`
	BackportCaveat  string          `json:"backportCaveat,omitempty"`
	Host            string          `json:"host"`
	Port            int             `json:"port"`
	Service         string          `json:"service"`
	Evidence        string          `json:"evidence"`
	Summary         string          `json:"summary"`
	Remediation     string          `json:"remediation"`
	NVDURL          string          `json:"nvdUrl"`
	CVEOrgURL       string          `json:"cveOrgUrl"`
	References      []ReferenceLink `json:"references"`
}

// Summary aggregates CVE findings across a full scan report.
type Summary struct {
	Total      int     `json:"total"`
	Critical   int     `json:"critical"`
	High       int     `json:"high"`
	Medium     int     `json:"medium"`
	Low        int     `json:"low"`
	MaxCVSS    float64 `json:"maxCvss"`
	OnlineUsed bool    `json:"onlineUsed,omitempty"`
}

type versionRange struct {
	minInclusive string // empty means unbounded below
	maxExclusive string // empty means unbounded above
	exact        string // non-empty means exact match only
}

type catalogEntry struct {
	cve            string
	productKey     string
	displayProduct string
	title          string
	ranges         []versionRange
	scopeLabel     string
	fixedVersion   string
	severity       string
	cvss           float64
	cvssVector     string
	cwe            string
	summary        string
	remediation    string
	vendorURL      string
	backportProne  bool
}

var (
	reOpenSSH  = regexp.MustCompile(`(?i)OpenSSH[_/\s-]([0-9]+\.[0-9]+(?:p[0-9]+)?)`)
	reDropbear = regexp.MustCompile(`(?i)dropbear[_/\s-]([0-9]{4}\.[0-9]+)`)
	reApache   = regexp.MustCompile(`(?i)Apache/([0-9]+\.[0-9]+\.[0-9]+)`)
	reNginx    = regexp.MustCompile(`(?i)\bnginx/([0-9]+\.[0-9]+\.[0-9]+)`)
	reOpenSSL  = regexp.MustCompile(`(?i)OpenSSL/([0-9]+\.[0-9]+\.[0-9]+[a-z]?)`)
	rePHP      = regexp.MustCompile(`(?i)\bPHP/([0-9]+\.[0-9]+\.[0-9]+)`)
	reIIS      = regexp.MustCompile(`(?i)Microsoft-IIS/([0-9]+\.[0-9]+)`)
	reTomcat   = regexp.MustCompile(`(?i)Tomcat/([0-9]+\.[0-9]+\.[0-9]+)`)
	reJetty    = regexp.MustCompile(`(?i)Jetty\(([0-9]+\.[0-9]+\.[0-9]+)`)
	reJenkins  = regexp.MustCompile(`(?i)Jenkins[\s/]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reVsftpd   = regexp.MustCompile(`(?i)vsFTPd\s+([0-9]+\.[0-9]+\.[0-9]+)`)
	reProFTPD  = regexp.MustCompile(`(?i)ProFTPD\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)`)
	reExim     = regexp.MustCompile(`(?i)\bExim\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reRedis    = regexp.MustCompile(`(?i)redis(?:_version)?[:/\s=]+([0-9]+\.[0-9]+\.[0-9]+)`)
	reMariaDB  = regexp.MustCompile(`(?i)MariaDB[-/\s:]+([0-9]+\.[0-9]+\.[0-9]+)`)
	reMySQL    = regexp.MustCompile(`(?i)\b([58]\.[0-9]+\.[0-9]+)(?:-MySQL|\b.*mysql)`)
	rePostgres = regexp.MustCompile(`(?i)PostgreSQL\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reDistro   = regexp.MustCompile(`(?i)\b(ubuntu|debian|el[0-9]|rhel|centos|alpine|fedora)\b`)
)

var catalog = []catalogEntry{
	// OpenSSH
	{
		cve:            "CVE-2024-6387",
		productKey:     "openssh",
		displayProduct: "OpenSSH",
		title:          "regreSSHion : condition de course signal handler dans sshd permettant une RCE",
		ranges:         []versionRange{{minInclusive: "8.5p1", maxExclusive: "9.8p1"}},
		scopeLabel:     ">= 8.5p1, < 9.8p1 (et < 4.4p1 si non patche)",
		fixedVersion:   "9.8p1",
		severity:       "high",
		cvss:           8.1,
		cvssVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-362",
		summary:        "Une condition de course asynchrone dans SIGALRM de sshd sur les systemes glibc permet une execution de code distant avant authentification.",
		remediation:    "Mettre a jour OpenSSH vers 9.8p1+ (ou le paquet securite de la distribution) ou definir LoginGraceTime 0 temporairement.",
		vendorURL:      "https://www.openssh.com/txt/release-9.8",
		backportProne:  true,
	},
	{
		cve:            "CVE-2023-48795",
		productKey:     "openssh",
		displayProduct: "OpenSSH",
		title:          "Terrapin : troncature de prefixe dans le handshake binaire SSH",
		ranges:         []versionRange{{maxExclusive: "9.6"}},
		scopeLabel:     "< 9.6p1 (si chacha20-poly1305 ou CBC-EtM actifs)",
		fixedVersion:   "9.6p1",
		severity:       "medium",
		cvss:           5.9,
		cvssVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
		cwe:            "CWE-354",
		summary:        "Un attaquant en position Man-in-the-Middle peut supprimer des messages d'extension lors de la negociation SSH sans detection d'integrite.",
		remediation:    "Activer l'extension strict KEX en mettant a jour OpenSSH vers 9.6p1 ou version ulterieure.",
		vendorURL:      "https://www.openssh.com/txt/release-9.6",
		backportProne:  true,
	},
	{
		cve:            "CVE-2023-38408",
		productKey:     "openssh",
		displayProduct: "OpenSSH",
		title:          "Execution de code distant via le transfert ssh-agent et bibliotheques PKCS#11",
		ranges:         []versionRange{{minInclusive: "5.5", maxExclusive: "9.3p2"}},
		scopeLabel:     ">= 5.5, < 9.3p2 (lorsque ForwardAgent est utilise)",
		fixedVersion:   "9.3p2",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-426",
		summary:        "Le support PKCS#11 de ssh-agent peut charger des bibliotheques partagees presentes sur le systeme si le socket d'agent est transfere vers un hote compromis.",
		remediation:    "Mettre a jour OpenSSH vers 9.3p2+ et desactiver ForwardAgent par defaut.",
		vendorURL:      "https://www.openssh.com/txt/release-9.3p2",
		backportProne:  true,
	},
	{
		cve:            "CVE-2021-41617",
		productKey:     "openssh",
		displayProduct: "OpenSSH",
		title:          "Elevation de privileges via AuthorizedKeysCommand / AuthorizedPrincipalsCommand",
		ranges:         []versionRange{{minInclusive: "6.2", maxExclusive: "8.8"}},
		scopeLabel:     ">= 6.2, < 8.8",
		fixedVersion:   "8.8",
		severity:       "high",
		cvss:           7.0,
		cvssVector:     "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-269",
		summary:        "sshd n'initialise pas correctement les groupes supplementaires lors de l'execution d'AuthorizedKeysCommand sous un utilisateur non-root.",
		remediation:    "Mettre a jour OpenSSH vers 8.8 ou appliquer le correctif de securite de la distribution.",
		vendorURL:      "https://www.openssh.com/txt/release-8.8",
		backportProne:  true,
	},
	{
		cve:            "CVE-2018-15473",
		productKey:     "openssh",
		displayProduct: "OpenSSH",
		title:          "Enumeration de comptes utilisateurs valides via requetes d'authentification malformees",
		ranges:         []versionRange{{maxExclusive: "7.8"}},
		scopeLabel:     "< 7.8",
		fixedVersion:   "7.8",
		severity:       "medium",
		cvss:           5.3,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		cwe:            "CWE-200",
		summary:        "Une reponse differenciee dans auth2-gss.c, auth2-hostbased.c et auth2-pubkey.c permet de verifier l'existence de comptes locaux.",
		remediation:    "Mettre a jour OpenSSH vers 7.8+.",
		vendorURL:      "https://www.openssh.com/txt/release-7.8",
		backportProne:  true,
	},

	// Apache HTTP Server
	{
		cve:            "CVE-2021-41773",
		productKey:     "apache",
		displayProduct: "Apache HTTP Server",
		title:          "Traversee de repertoires (Path Traversal) et RCE CGI dans Apache 2.4.49",
		ranges:         []versionRange{{exact: "2.4.49"}},
		scopeLabel:     "== 2.4.49",
		fixedVersion:   "2.4.51",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-22",
		summary:        "Une erreur de normalisation d'URL dans Apache 2.4.49 permet de lire des fichiers hors DocumentRoot et d'executer du code si mod_cgi est actif.",
		remediation:    "Mettre a jour immediatement Apache HTTP Server vers 2.4.51+ (idealement 2.4.62+).",
		vendorURL:      "https://httpd.apache.org/security/vulnerabilities_24.html",
		backportProne:  false,
	},
	{
		cve:            "CVE-2021-42013",
		productKey:     "apache",
		displayProduct: "Apache HTTP Server",
		title:          "Contournement du correctif de Path Traversal et RCE dans Apache 2.4.49 et 2.4.50",
		ranges:         []versionRange{{minInclusive: "2.4.49", maxExclusive: "2.4.51"}},
		scopeLabel:     ">= 2.4.49, < 2.4.51",
		fixedVersion:   "2.4.51",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-22",
		summary:        "Le correctif initial de CVE-2021-41773 dans 2.4.50 etait incomplet face au double encodage URL, permettant lecture arbitraire et RCE.",
		remediation:    "Mettre a jour Apache HTTP Server vers 2.4.51 ou plus recent.",
		vendorURL:      "https://httpd.apache.org/security/vulnerabilities_24.html",
		backportProne:  false,
	},
	{
		cve:            "CVE-2023-25690",
		productKey:     "apache",
		displayProduct: "Apache HTTP Server",
		title:          "HTTP Request Smuggling dans mod_proxy avec RewriteRule ou ProxyPassMatch",
		ranges:         []versionRange{{minInclusive: "2.4.0", maxExclusive: "2.4.56"}},
		scopeLabel:     ">= 2.4.0, < 2.4.56",
		fixedVersion:   "2.4.56",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-444",
		summary:        "Certaines configurations RewriteRule ou ProxyPassMatch de mod_proxy permettent l'injection d'en-tetes et la dissimulation de requetes HTTP.",
		remediation:    "Mettre a jour Apache HTTP Server vers 2.4.56+ et verifier les regles RewriteRule.",
		vendorURL:      "https://httpd.apache.org/security/vulnerabilities_24.html",
		backportProne:  true,
	},
	{
		cve:            "CVE-2024-38476",
		productKey:     "apache",
		displayProduct: "Apache HTTP Server",
		title:          "Divulgation d'informations, SSRF ou execution de scripts locaux via reponses backend",
		ranges:         []versionRange{{minInclusive: "2.4.0", maxExclusive: "2.4.60"}},
		scopeLabel:     ">= 2.4.0, < 2.4.60",
		fixedVersion:   "2.4.60",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-829",
		summary:        "Des reponses malveillantes ou forgees depuis des services backend peuvent declencher des redirections internes dangereuses dans httpd.",
		remediation:    "Mettre a jour Apache HTTP Server vers 2.4.62+.",
		vendorURL:      "https://httpd.apache.org/security/vulnerabilities_24.html",
		backportProne:  true,
	},

	// nginx
	{
		cve:            "CVE-2021-23017",
		productKey:     "nginx",
		displayProduct: "nginx",
		title:          "Ecriture memoire hors limites d'un octet dans le resolveur DNS nginx",
		ranges:         []versionRange{{minInclusive: "0.6.18", maxExclusive: "1.20.1"}},
		scopeLabel:     ">= 0.6.18, < 1.20.1 (directive resolver requise)",
		fixedVersion:   "1.20.1 / 1.21.0",
		severity:       "high",
		cvss:           7.7,
		cvssVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H",
		cwe:            "CWE-193",
		summary:        "Une reponse DNS forgee lors du traitement de ngx_resolver_copy permet un deni de service ou une corruption memoire lorsque la directive resolver est configuree.",
		remediation:    "Mettre a jour nginx vers 1.20.1+, 1.21.0+ ou une branche LTS maintenue.",
		vendorURL:      "https://nginx.org/en/security_advisories.html",
		backportProne:  true,
	},
	{
		cve:            "CVE-2022-41741",
		productKey:     "nginx",
		displayProduct: "nginx",
		title:          "Corruption memoire dans le module ngx_http_mp4_module",
		ranges:         []versionRange{{minInclusive: "1.1.3", maxExclusive: "1.22.1"}},
		scopeLabel:     ">= 1.1.3, < 1.22.1 (si module mp4 active)",
		fixedVersion:   "1.22.1 / 1.23.2",
		severity:       "high",
		cvss:           7.8,
		cvssVector:     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-787",
		summary:        "Un fichier MP4 specialement concu peut corrompre la memoire d'un processus worker nginx lorsque la directive mp4 est utilisee.",
		remediation:    "Mettre a jour nginx vers 1.22.1+ ou 1.23.2+.",
		vendorURL:      "https://nginx.org/en/security_advisories.html",
		backportProne:  true,
	},
	{
		cve:            "CVE-2023-44487",
		productKey:     "nginx",
		displayProduct: "nginx",
		title:          "HTTP/2 Rapid Reset : deni de service par annulation massive de flux",
		ranges:         []versionRange{{minInclusive: "1.9.5", maxExclusive: "1.25.3"}},
		scopeLabel:     ">= 1.9.5, < 1.25.3 (si HTTP/2 active)",
		fixedVersion:   "1.25.3",
		severity:       "high",
		cvss:           7.5,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		cwe:            "CWE-400",
		summary:        "L'envoi rapide de trames HEADERS suivies de RST_STREAM en HTTP/2 permet d'epuiser les ressources CPU du serveur.",
		remediation:    "Mettre a jour nginx vers 1.25.3+ et conserver keepalive_requests dans des bornes raisonnables.",
		vendorURL:      "https://www.nginx.com/blog/http-2-rapid-reset-attack-impacting-f5-nginx-products/",
		backportProne:  true,
	},

	// OpenSSL
	{
		cve:            "CVE-2014-0160",
		productKey:     "openssl",
		displayProduct: "OpenSSL",
		title:          "Heartbleed : divulgation de memoire serveur via l'extension TLS Heartbeat",
		ranges:         []versionRange{{minInclusive: "1.0.1", maxExclusive: "1.0.1g"}},
		scopeLabel:     ">= 1.0.1, < 1.0.1g",
		fixedVersion:   "1.0.1g",
		severity:       "high",
		cvss:           7.5,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		cwe:            "CWE-125",
		summary:        "Une lecture hors limites dans l'extension TLS/DTLS Heartbeat permet d'extraire jusqu'a 64 Ko de memoire vive par requete (cles privees, jetons).",
		remediation:    "Mettre a jour OpenSSL vers une branche supportee (3.x), revoquer et regenerer les certificats et cles privees.",
		vendorURL:      "https://www.openssl.org/news/secadv/20140407.txt",
		backportProne:  true,
	},
	{
		cve:            "CVE-2022-3602",
		productKey:     "openssl",
		displayProduct: "OpenSSL",
		title:          "Depassement de tampon 4 octets lors de la verification de contraintes Punycode X.509",
		ranges:         []versionRange{{minInclusive: "3.0.0", maxExclusive: "3.0.7"}},
		scopeLabel:     ">= 3.0.0, < 3.0.7",
		fixedVersion:   "3.0.7",
		severity:       "high",
		cvss:           7.5,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		cwe:            "CWE-120",
		summary:        "Le decodage d'une contrainte de nom d'email punycode dans une chaine de certificats X.509 provoque un depassement de pile de 4 octets.",
		remediation:    "Mettre a jour OpenSSL vers 3.0.7 ou version ulterieure.",
		vendorURL:      "https://www.openssl.org/news/secadv/20221101.txt",
		backportProne:  true,
	},
	{
		cve:            "CVE-2022-0778",
		productKey:     "openssl",
		displayProduct: "OpenSSL",
		title:          "Boucle infinie dans BN_mod_sqrt() lors de l'analyse de certificats malformes",
		ranges: []versionRange{
			{minInclusive: "1.0.2", maxExclusive: "1.1.1n"},
			{minInclusive: "3.0.0", maxExclusive: "3.0.2"},
		},
		scopeLabel:    ">= 1.0.2, < 1.1.1n ou >= 3.0.0, < 3.0.2",
		fixedVersion:  "1.1.1n / 3.0.2",
		severity:      "high",
		cvss:          7.5,
		cvssVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		cwe:           "CWE-835",
		summary:       "Un certificat contenant des parametres de courbe elliptique invalides bloque indefiniment le thread d'analyse TLS.",
		remediation:   "Mettre a jour OpenSSL vers 1.1.1n+ ou 3.0.2+.",
		vendorURL:     "https://www.openssl.org/news/secadv/20220315.txt",
		backportProne: true,
	},

	// PHP
	{
		cve:            "CVE-2024-4577",
		productKey:     "php",
		displayProduct: "PHP",
		title:          "Injection d'arguments dans PHP-CGI permettant l'execution de code distant",
		ranges: []versionRange{
			{maxExclusive: "8.1.29"},
			{minInclusive: "8.2.0", maxExclusive: "8.2.20"},
			{minInclusive: "8.3.0", maxExclusive: "8.3.8"},
		},
		scopeLabel:    "< 8.1.29, >= 8.2.0 < 8.2.20, >= 8.3.0 < 8.3.8 (principalement Windows CGI)",
		fixedVersion:  "8.1.29 / 8.2.20 / 8.3.8",
		severity:      "critical",
		cvss:          9.8,
		cvssVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:           "CWE-78",
		summary:       "La conversion Best-Fit des pages de codes sous Windows permet d'injecter des options de ligne de commande a php-cgi.exe.",
		remediation:   "Mettre a jour PHP vers 8.1.29+, 8.2.20+ ou 8.3.8+, et migrer de CGI vers FastCGI / PHP-FPM.",
		vendorURL:     "https://www.php.net/ChangeLog-8.php",
		backportProne: true,
	},
	{
		cve:            "CVE-2019-11043",
		productKey:     "php",
		displayProduct: "PHP",
		title:          "Sous-depassement de pointeur dans PHP-FPM derriere nginx permettant une RCE",
		ranges:         []versionRange{{minInclusive: "7.1.0", maxExclusive: "7.3.11"}},
		scopeLabel:     ">= 7.1.0, < 7.3.11 (configurations nginx fastcgi_split_path_info)",
		fixedVersion:   "7.2.24 / 7.3.11",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-787",
		summary:        "Une expression reguliere fastcgi_split_path_info combinee a un caractere saut de ligne permet d'ecraser les variables FCGI internes.",
		remediation:    "Mettre a jour PHP vers une version 8.x supportee et corriger la configuration fastcgi nginx.",
		vendorURL:      "https://bugs.php.net/bug.php?id=78599",
		backportProne:  true,
	},

	// FTP / Mail / Databases / App Servers
	{
		cve:            "CVE-2011-2523",
		productKey:     "vsftpd",
		displayProduct: "vsFTPd",
		title:          "Porte derobee malveillante dans l'archive officielle vsFTPd 2.3.4",
		ranges:         []versionRange{{exact: "2.3.4"}},
		scopeLabel:     "== 2.3.4",
		fixedVersion:   "3.0.0+",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-506",
		summary:        "L'archive source compromise de vsftpd 2.3.4 ouvre un shell root sur le port 6200 lors d'une connexion contenant la sequence ':)'.",
		remediation:    "Remplacer immediatement le binaire vsftpd par un paquet authentifie issu d'un depot officiel.",
		vendorURL:      "https://security.appspot.com/vsftpd.html",
		backportProne:  false,
	},
	{
		cve:            "CVE-2015-3306",
		productKey:     "proftpd",
		displayProduct: "ProFTPD",
		title:          "Copie arbitraire de fichiers sans authentification via mod_copy (SITE CPFR/CPTO)",
		ranges:         []versionRange{{maxExclusive: "1.3.5a"}},
		scopeLabel:     "<= 1.3.5 (si le module mod_copy est charge)",
		fixedVersion:   "1.3.5a",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-284",
		summary:        "Les commandes SITE CPFR et SITE CPTO de mod_copy sont accessibles aux clients non authentifies.",
		remediation:    "Desactiver mod_copy ou mettre a jour ProFTPD vers 1.3.5a+ / 1.3.8+.",
		vendorURL:      "http://bugs.proftpd.org/show_bug.cgi?id=4169",
		backportProne:  false,
	},
	{
		cve:            "CVE-2019-10149",
		productKey:     "exim",
		displayProduct: "Exim",
		title:          "Return of the Wizard : execution de commandes distantes dans Exim",
		ranges:         []versionRange{{minInclusive: "4.87", maxExclusive: "4.92"}},
		scopeLabel:     ">= 4.87, < 4.92",
		fixedVersion:   "4.92",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-78",
		summary:        "Une validation incorrecte de l'adresse destinataire dans deliver_message() permet l'execution de commandes en tant que root.",
		remediation:    "Mettre a jour Exim vers 4.96.2 ou plus recent.",
		vendorURL:      "https://www.exim.org/static/doc/security/CVE-2019-10149.txt",
		backportProne:  true,
	},
	{
		cve:            "CVE-2023-42115",
		productKey:     "exim",
		displayProduct: "Exim",
		title:          "Ecriture hors limites dans le mecanisme SMTP EXTERNAL AUTH d'Exim",
		ranges:         []versionRange{{maxExclusive: "4.96.1"}},
		scopeLabel:     "< 4.96.1",
		fixedVersion:   "4.96.1",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-787",
		summary:        "Une validation insuffisante dans l'authentification SMTP EXTERNAL permet une ecriture hors limites exploitable a distance.",
		remediation:    "Mettre a jour Exim vers 4.96.1 ou version ulterieure.",
		vendorURL:      "https://www.exim.org/static/doc/security/CVE-2023-42115.txt",
		backportProne:  true,
	},
	{
		cve:            "CVE-2022-0543",
		productKey:     "redis",
		displayProduct: "Redis",
		title:          "Evasion du bac a sable Lua sur paquets Debian/Ubuntu permettant une RCE",
		ranges:         []versionRange{{maxExclusive: "6.2.7"}},
		scopeLabel:     "< 6.2.7 (paquets Debian/Ubuntu liant dynamiquement liblua)",
		fixedVersion:   "6.2.7 / correctif paquet Debian",
		severity:       "critical",
		cvss:           10.0,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		cwe:            "CWE-829",
		summary:        "La variable globale package reste accessible dans l'environnement Lua sur certaines compilations Linux, permettant de charger des bibliotheques arbitraires.",
		remediation:    "Ne jamais exposer Redis sans authentification sur le reseau et mettre a jour les paquets Redis.",
		vendorURL:      "https://www.debian.org/security/2022/dsa-5081",
		backportProne:  true,
	},
	{
		cve:            "CVE-2020-1938",
		productKey:     "tomcat",
		displayProduct: "Apache Tomcat",
		title:          "Ghostcat : lecture de fichiers et inclusion via le connecteur AJP (port 8009)",
		ranges:         []versionRange{{minInclusive: "9.0.0", maxExclusive: "9.0.31"}, {minInclusive: "8.5.0", maxExclusive: "8.5.51"}},
		scopeLabel:     ">= 8.5.0 < 8.5.51 ou >= 9.0.0 < 9.0.31",
		fixedVersion:   "8.5.51 / 9.0.31",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-200",
		summary:        "Le connecteur AJP de Tomcat fait confiance aux attributs entrants sans secret partage, permettant de lire tout fichier de l'application Web.",
		remediation:    "Desactiver le connecteur AJP s'il est inutilise ou configurer secretRequired=true apres mise a jour.",
		vendorURL:      "https://tomcat.apache.org/security-9.html",
		backportProne:  false,
	},
	{
		cve:            "CVE-2024-23897",
		productKey:     "jenkins",
		displayProduct: "Jenkins",
		title:          "Lecture arbitraire de fichiers sur le controleur Jenkins via l'analyseur CLI args4j",
		ranges:         []versionRange{{maxExclusive: "2.442"}},
		scopeLabel:     "< 2.442 (et LTS < 2.426.3)",
		fixedVersion:   "2.442 / LTS 2.426.3",
		severity:       "critical",
		cvss:           9.8,
		cvssVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		cwe:            "CWE-200",
		summary:        "La fonctionnalite @fichier d'args4j dans la CLI Jenkins permet de lire des fichiers sensibles du serveur sans authentification complete.",
		remediation:    "Mettre a jour Jenkins vers 2.442+ ou LTS 2.426.3+ et restreindre l'acces CLI.",
		vendorURL:      "https://www.jenkins.io/security/advisory/2024-01-24/",
		backportProne:  false,
	},
}

func nvdLink(cve string) string {
	return "https://nvd.nist.gov/vuln/detail/" + cve
}

func cveOrgLink(cve string) string {
	return "https://www.cve.org/CVERecord?id=" + cve
}

func buildRefs(cve, vendorLabel, vendorURL string) []ReferenceLink {
	refs := []ReferenceLink{
		{Label: "NVD (NIST)", URL: nvdLink(cve)},
		{Label: "CVE.org (MITRE)", URL: cveOrgLink(cve)},
	}
	if vendorURL != "" {
		lbl := "Bulletin editeur"
		if vendorLabel != "" {
			lbl = "Avis " + vendorLabel
		}
		refs = append(refs, ReferenceLink{Label: lbl, URL: vendorURL})
	}
	return refs
}

type verToken struct {
	isNum bool
	num   int
	str   string
}

func tokenizeVersion(v string) []verToken {
	s := strings.TrimSpace(strings.ToLower(v))
	var tokens []verToken
	i := 0
	for i < len(s) {
		ch := rune(s[i])
		if ch == '.' || ch == '_' || ch == '-' || ch == '+' {
			i++
			continue
		}
		if unicode.IsDigit(ch) {
			j := i
			for j < len(s) && unicode.IsDigit(rune(s[j])) {
				j++
			}
			n, _ := strconv.Atoi(s[i:j])
			tokens = append(tokens, verToken{isNum: true, num: n})
			i = j
			continue
		}
		if unicode.IsLetter(ch) {
			j := i
			for j < len(s) && unicode.IsLetter(rune(s[j])) {
				j++
			}
			tokens = append(tokens, verToken{isNum: false, str: s[i:j]})
			i = j
			continue
		}
		i++
	}
	return tokens
}

// CompareVersion compares two software version strings deterministically (-1, 0, +1),
// handling numeric components, OpenSSH patch suffixes (9.2p1 < 9.8p1), and OpenSSL
// letter suffixes (1.0.1 < 1.0.1f < 1.0.1g).
func CompareVersion(a, b string) int {
	ta := tokenizeVersion(a)
	tb := tokenizeVersion(b)
	maxLen := len(ta)
	if len(tb) > maxLen {
		maxLen = len(tb)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(ta) {
			// Trailing zero tokens equal missing numeric suffix (e.g. 9.6 == 9.6.0),
			// whereas a trailing patch letter/suffix ("p1", "g") makes b greater than a.
			if tb[i].isNum && tb[i].num == 0 {
				continue
			}
			return -1
		}
		if i >= len(tb) {
			if ta[i].isNum && ta[i].num == 0 {
				continue
			}
			return 1
		}
		va, vb := ta[i], tb[i]
		if va.isNum && vb.isNum {
			if va.num < vb.num {
				return -1
			}
			if va.num > vb.num {
				return 1
			}
			continue
		}
		if va.isNum != vb.isNum {
			// Number takes precedence over patch suffix at the same position (1.0.1.1 > 1.0.1g)
			if va.isNum {
				return 1
			}
			return -1
		}
		if va.str < vb.str {
			return -1
		}
		if va.str > vb.str {
			return 1
		}
	}
	return 0
}

func matchesRanges(ver string, ranges []versionRange) bool {
	for _, r := range ranges {
		if r.exact != "" {
			if CompareVersion(ver, r.exact) == 0 {
				return true
			}
			continue
		}
		if r.minInclusive != "" && CompareVersion(ver, r.minInclusive) < 0 {
			continue
		}
		if r.maxExclusive != "" && CompareVersion(ver, r.maxExclusive) >= 0 {
			continue
		}
		return true
	}
	return false
}

// ExtractComponents passively parses software product & version strings from banners and HTTP headers.
func ExtractComponents(svc services.ServiceInfo, insp *inspector.Result) []Component {
	var sources []struct {
		src  string
		text string
	}
	if insp != nil {
		if insp.Banner != "" {
			sources = append(sources, struct{ src, text string }{"banner", insp.Banner})
		}
		if insp.HTTP != nil {
			if insp.HTTP.Server != "" {
				sources = append(sources, struct{ src, text string }{"http-server", insp.HTTP.Server})
			}
			if insp.HTTP.PoweredBy != "" {
				sources = append(sources, struct{ src, text string }{"http-powered-by", insp.HTTP.PoweredBy})
			}
		}
	}
	if len(sources) == 0 && svc.Product != "" {
		sources = append(sources, struct{ src, text string }{"service", svc.Product})
	}

	type matcher struct {
		re      *regexp.Regexp
		vendor  string
		product string
		display string
	}
	matchers := []matcher{
		{reOpenSSH, "openbsd", "openssh", "OpenSSH"},
		{reDropbear, "dropbear_ssh_project", "dropbear_ssh", "Dropbear SSH"},
		{reApache, "apache", "http_server", "Apache HTTP Server"},
		{reNginx, "f5", "nginx", "nginx"},
		{reOpenSSL, "openssl", "openssl", "OpenSSL"},
		{rePHP, "php", "php", "PHP"},
		{reIIS, "microsoft", "internet_information_services", "Microsoft IIS"},
		{reTomcat, "apache", "tomcat", "Apache Tomcat"},
		{reJetty, "eclipse", "jetty", "Eclipse Jetty"},
		{reJenkins, "jenkins", "jenkins", "Jenkins"},
		{reVsftpd, "beasts", "vsftpd", "vsFTPd"},
		{reProFTPD, "proftpd", "proftpd", "ProFTPD"},
		{reExim, "exim", "exim", "Exim"},
		{reRedis, "redis", "redis", "Redis"},
		{reMariaDB, "mariadb", "mariadb", "MariaDB"},
		{reMySQL, "oracle", "mysql", "MySQL"},
		{rePostgres, "postgresql", "postgresql", "PostgreSQL"},
	}

	seen := make(map[string]struct{})
	var comps []Component
	for _, item := range sources {
		distro := ""
		if dm := reDistro.FindString(item.text); dm != "" {
			distro = strings.ToLower(dm)
		}
		for _, m := range matchers {
			sub := m.re.FindStringSubmatch(item.text)
			if len(sub) < 2 {
				continue
			}
			ver := sub[1]
			key := m.product + ":" + ver
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", m.vendor, m.product, strings.ToLower(ver))
			comps = append(comps, Component{
				Vendor:     m.vendor,
				Product:    m.product,
				Display:    m.display,
				Version:    ver,
				DistroHint: distro,
				CPE:        cpe,
				Source:     item.src,
			})
		}
	}
	return comps
}

func productCatalogKey(compProduct string) string {
	if compProduct == "http_server" {
		return "apache"
	}
	return compProduct
}

// MatchPort evaluates passive service, banner, HTTP, and TLS clues for known CVEs.
func MatchPort(host string, port int, svc services.ServiceInfo, insp *inspector.Result) []AdvisoryMatch {
	var out []AdvisoryMatch
	seen := make(map[string]struct{})

	comps := ExtractComponents(svc, insp)
	for _, comp := range comps {
		pKey := productCatalogKey(comp.Product)
		for _, entry := range catalog {
			if entry.productKey != pKey {
				continue
			}
			if !matchesRanges(comp.Version, entry.ranges) {
				continue
			}
			if _, dup := seen[entry.cve]; dup {
				continue
			}
			seen[entry.cve] = struct{}{}

			confidence := "banner-version"
			caveat := ""
			if entry.backportProne {
				if comp.DistroHint != "" {
					confidence = "distro-backport-possible"
					caveat = fmt.Sprintf("Banniere %s detectee : verifiez la version du paquet systeme (%s retroporte souvent les correctifs sans modifier le numero amont).",
						comp.DistroHint, comp.DistroHint)
				} else {
					caveat = "Correspondance basee sur la version annoncee en banniere ; sur Linux, verifiez si un correctif distribution est deja applique."
				}
			}

			out = append(out, AdvisoryMatch{
				CVE:             entry.cve,
				Title:           entry.title,
				Product:         entry.displayProduct,
				DetectedVersion: comp.Version,
				CPE:             comp.CPE,
				AffectedScope:   entry.scopeLabel,
				FixedVersion:    entry.fixedVersion,
				Severity:        entry.severity,
				CVSS:            entry.cvss,
				CVSSVector:      entry.cvssVector,
				CWE:             entry.cwe,
				Confidence:      confidence,
				BackportCaveat:  caveat,
				Host:            host,
				Port:            port,
				Service:         svc.ID,
				Evidence:        fmt.Sprintf("%s %s (source: %s)", comp.Display, comp.Version, comp.Source),
				Summary:         entry.summary,
				Remediation:     entry.remediation,
				NVDURL:          nvdLink(entry.cve),
				CVEOrgURL:       cveOrgLink(entry.cve),
				References:      buildRefs(entry.cve, entry.displayProduct, entry.vendorURL),
			})
		}
	}

	// Protocol-verified cryptographic vulnerabilities on live TLS handshakes
	if insp != nil && insp.TLS != nil && insp.TLS.Established {
		proto := strings.ToUpper(strings.TrimSpace(insp.TLS.Protocol))
		if proto == "SSL3.0" || proto == "SSLV3" {
			cve := "CVE-2014-3566"
			seen[cve] = struct{}{}
			out = append(out, AdvisoryMatch{
				CVE:             cve,
				Title:           "POODLE : divulgation de texte clair sur remplissage CBC SSLv3",
				Product:         "SSL/TLS Stack",
				DetectedVersion: insp.TLS.Protocol,
				AffectedScope:   "Protocole SSL 3.0 actif",
				FixedVersion:    "TLS 1.2 / TLS 1.3",
				Severity:        "high",
				CVSS:            7.5,
				CVSSVector:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
				CWE:             "CWE-310",
				Confidence:      "protocol-verified",
				Host:            host,
				Port:            port,
				Service:         svc.ID,
				Evidence:        fmt.Sprintf("Handshake negocie en %s sur %s:%d", insp.TLS.Protocol, host, port),
				Summary:         "Le protocole SSL 3.0 permet le dechiffrement octet par octet via une attaque Padding Oracle.",
				Remediation:     "Desactiver SSLv3, TLS 1.0 et TLS 1.1 ; imposer TLS 1.2 et TLS 1.3.",
				NVDURL:          nvdLink(cve),
				CVEOrgURL:       cveOrgLink(cve),
				References:      buildRefs(cve, "IETF RFC 7568", "https://datatracker.ietf.org/doc/html/rfc7568"),
			})
		} else if proto == "TLSV1" || proto == "TLSV1.0" || proto == "TLS 1.0" {
			cve := "CVE-2011-3389"
			seen[cve] = struct{}{}
			out = append(out, AdvisoryMatch{
				CVE:             cve,
				Title:           "BEAST : faiblesse des vecteurs d'initialisation CBC dans TLS 1.0",
				Product:         "TLS Stack",
				DetectedVersion: insp.TLS.Protocol,
				AffectedScope:   "Protocole TLS 1.0 actif (obsolete selon RFC 8996)",
				FixedVersion:    "TLS 1.2 / TLS 1.3",
				Severity:        "medium",
				CVSS:            5.3,
				CVSSVector:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
				CWE:             "CWE-326",
				Confidence:      "protocol-verified",
				Host:            host,
				Port:            port,
				Service:         svc.ID,
				Evidence:        fmt.Sprintf("Protocole obsolete %s accepte sur %s:%d", insp.TLS.Protocol, host, port),
				Summary:         "TLS 1.0 utilise des IV chaines previsibles pour les suites CBC et est officiellement deprecie par l'IETF (RFC 8996).",
				Remediation:     "Desactiver TLS 1.0 et TLS 1.1 dans la configuration TLS du service.",
				NVDURL:          nvdLink(cve),
				CVEOrgURL:       cveOrgLink(cve),
				References:      buildRefs(cve, "IETF RFC 8996", "https://datatracker.ietf.org/doc/html/rfc8996"),
			})
		}

		if insp.TLS.Cipher != nil {
			ciph := strings.ToUpper(insp.TLS.Cipher.Name)
			if strings.Contains(ciph, "3DES") || strings.Contains(ciph, "DES-CBC3") {
				cve := "CVE-2016-2183"
				if _, ok := seen[cve]; !ok {
					seen[cve] = struct{}{}
					out = append(out, AdvisoryMatch{
						CVE:             cve,
						Title:           "SWEET32 : collisions de blocs 64 bits sur les chiffrements 3DES",
						Product:         "TLS Cipher Suite",
						DetectedVersion: insp.TLS.Cipher.Name,
						AffectedScope:   "Suites TLS/SSH basées sur Triple-DES (blocs 64 bits)",
						FixedVersion:    "AES-GCM / ChaCha20-Poly1305",
						Severity:        "medium",
						CVSS:            5.9,
						CVSSVector:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						CWE:             "CWE-326",
						Confidence:      "protocol-verified",
						Host:            host,
						Port:            port,
						Service:         svc.ID,
						Evidence:        fmt.Sprintf("Suite negociee : %s", insp.TLS.Cipher.Name),
						Summary:         "Les chiffrements par blocs de 64 bits comme 3DES sont vulnerables aux attaques par anniversaire sur les connexions longues.",
						Remediation:     "Retirer 3DES de la liste des suites autorisees au profit d'AES-128/256-GCM et ChaCha20-Poly1305.",
						NVDURL:          nvdLink(cve),
						CVEOrgURL:       cveOrgLink(cve),
						References:      buildRefs(cve, "SWEET32", "https://sweet32.info/"),
					})
				}
			}
			if strings.Contains(ciph, "RC4") {
				cve := "CVE-2013-2566"
				if _, ok := seen[cve]; !ok {
					seen[cve] = struct{}{}
					out = append(out, AdvisoryMatch{
						CVE:             cve,
						Title:           "Biais statistiques dans le chiffrement de flux RC4 sous TLS",
						Product:         "TLS Cipher Suite",
						DetectedVersion: insp.TLS.Cipher.Name,
						AffectedScope:   "Toutes suites TLS utilisant RC4 (interdit par RFC 7465)",
						FixedVersion:    "AES-GCM / ChaCha20-Poly1305",
						Severity:        "medium",
						CVSS:            5.9,
						CVSSVector:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						CWE:             "CWE-326",
						Confidence:      "protocol-verified",
						Host:            host,
						Port:            port,
						Service:         svc.ID,
						Evidence:        fmt.Sprintf("Suite negociee : %s", insp.TLS.Cipher.Name),
						Summary:         "RC4 presente des biais statistiques exploitables pour recuperer des octets repetitifs (cookies, jetons) dans un flux TLS.",
						Remediation:     "Interdire totalement RC4 conformement a la RFC 7465.",
						NVDURL:          nvdLink(cve),
						CVEOrgURL:       cveOrgLink(cve),
						References:      buildRefs(cve, "IETF RFC 7465", "https://datatracker.ietf.org/doc/html/rfc7465"),
					})
				}
			}
		}
	}

	sortMatches(out)
	return out
}

func sevRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sortMatches(list []AdvisoryMatch) {
	sort.Slice(list, func(i, j int) bool {
		ri, rj := sevRank(list[i].Severity), sevRank(list[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if list[i].CVSS != list[j].CVSS {
			return list[i].CVSS > list[j].CVSS
		}
		if list[i].Host != list[j].Host {
			return list[i].Host < list[j].Host
		}
		if list[i].Port != list[j].Port {
			return list[i].Port < list[j].Port
		}
		return list[i].CVE < list[j].CVE
	})
}

// Summarize computes aggregate counts and maximum CVSS across a slice of CVE matches.
func Summarize(matches []AdvisoryMatch, onlineUsed bool) Summary {
	s := Summary{OnlineUsed: onlineUsed}
	for _, m := range matches {
		s.Total++
		if m.CVSS > s.MaxCVSS {
			s.MaxCVSS = m.CVSS
		}
		switch strings.ToLower(m.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		default:
			s.Low++
		}
	}
	return s
}

// OnlineOptions configures live NVD REST API v2.0 enrichment.
type OnlineOptions struct {
	BaseURL    string
	HTTPClient *http.Client
	MaxPerCPE  int
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssV30 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// LookupOnlineNVD queries the NIST NVD v2.0 CPE endpoint and merges additional CVEs into existing.
func LookupOnlineNVD(ctx context.Context, host string, port int, svc services.ServiceInfo, insp *inspector.Result, existing []AdvisoryMatch, opts OnlineOptions) []AdvisoryMatch {
	comps := ExtractComponents(svc, insp)
	if len(comps) == 0 {
		return existing
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Second}
	}
	maxPerCPE := opts.MaxPerCPE
	if maxPerCPE <= 0 {
		maxPerCPE = 8
	}

	seen := make(map[string]struct{}, len(existing))
	for _, m := range existing {
		seen[m.CVE] = struct{}{}
	}
	merged := append([]AdvisoryMatch(nil), existing...)

	for _, comp := range comps {
		reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		u := fmt.Sprintf("%s?cpeName=%s&resultsPerPage=%d", baseURL, url.QueryEscape(comp.CPE), maxPerCPE)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Sentinel-Net-Defensive-Scanner/1.2")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		raw, rErr := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
		_ = resp.Body.Close()
		cancel()
		if rErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		var doc nvdResponse
		if json.Unmarshal(raw, &doc) != nil {
			continue
		}

		for _, item := range doc.Vulnerabilities {
			cveID := strings.TrimSpace(item.CVE.ID)
			if cveID == "" {
				continue
			}
			if _, ok := seen[cveID]; ok {
				continue
			}
			seen[cveID] = struct{}{}

			desc := ""
			for _, d := range item.CVE.Descriptions {
				if d.Lang == "fr" {
					desc = d.Value
					break
				}
				if d.Lang == "en" && desc == "" {
					desc = d.Value
				}
			}
			if len(desc) > 280 {
				desc = desc[:277] + "..."
			}

			score := 5.0
			sev := "medium"
			vec := ""
			if len(item.CVE.Metrics.CvssV31) > 0 {
				d := item.CVE.Metrics.CvssV31[0].CvssData
				score = d.BaseScore
				sev = strings.ToLower(d.BaseSeverity)
				vec = d.VectorString
			} else if len(item.CVE.Metrics.CvssV30) > 0 {
				d := item.CVE.Metrics.CvssV30[0].CvssData
				score = d.BaseScore
				sev = strings.ToLower(d.BaseSeverity)
				vec = d.VectorString
			}
			if sev != "critical" && sev != "high" && sev != "medium" && sev != "low" {
				sev = "medium"
			}

			cwe := ""
			if len(item.CVE.Weaknesses) > 0 && len(item.CVE.Weaknesses[0].Description) > 0 {
				cwe = item.CVE.Weaknesses[0].Description[0].Value
			}

			merged = append(merged, AdvisoryMatch{
				CVE:             cveID,
				Title:           fmt.Sprintf("%s : vulnerabilite referencee NVD (%s)", comp.Display, cveID),
				Product:         comp.Display,
				DetectedVersion: comp.Version,
				CPE:             comp.CPE,
				AffectedScope:   fmt.Sprintf("Correspondance CPE %s %s (NVD)", comp.Display, comp.Version),
				Severity:        sev,
				CVSS:            score,
				CVSSVector:      vec,
				CWE:             cwe,
				Confidence:      "online-nvd",
				Host:            host,
				Port:            port,
				Service:         svc.ID,
				Evidence:        fmt.Sprintf("%s %s (%s)", comp.Display, comp.Version, comp.CPE),
				Summary:         desc,
				Remediation:     fmt.Sprintf("Consulter la fiche officielle %s et mettre a jour %s vers une version corrigee.", cveID, comp.Display),
				NVDURL:          nvdLink(cveID),
				CVEOrgURL:       cveOrgLink(cveID),
				References:      buildRefs(cveID, comp.Display, ""),
			})
		}
	}

	sortMatches(merged)
	return merged
}
