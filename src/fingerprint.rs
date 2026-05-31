use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub port: u16,
    pub service: String,
    pub protocol: String,
    pub probes: Vec<Probe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub probe_type: ProbeType,
    pub data: String,
    pub match_patterns: Vec<MatchPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeType {
    TcpBanner,
    UdpBanner,
    HttpGet,
    SslHello,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchPattern {
    pub pattern: String,
    pub service_name: String,
    pub version_info: String,
}

pub struct FingerprintDB {
    #[allow(dead_code)]
    fingerprints: Vec<ServiceFingerprint>,
    probe_map: HashMap<u16, Vec<ServiceFingerprint>>,
}

impl FingerprintDB {
    pub fn new() -> Self {
        let fingerprints = build_default_fingerprints();
        let mut probe_map: HashMap<u16, Vec<ServiceFingerprint>> = HashMap::new();
        for fp in &fingerprints {
            probe_map.entry(fp.port).or_default().push(fp.clone());
        }
        FingerprintDB {
            fingerprints,
            probe_map,
        }
    }

    pub fn identify_by_port(&self, port: u16) -> Option<&ServiceFingerprint> {
        self.probe_map.get(&port).and_then(|fps| fps.first())
    }

    pub fn identify_by_banner(&self, banner: &str, port: u16) -> ServiceMatch {
        let empty = ServiceMatch {
            service: "unknown".to_string(),
            version: String::new(),
            confidence: 0,
        };

        let fps = match self.probe_map.get(&port) {
            Some(f) => f,
            None => return empty,
        };

        for fp in fps {
            for probe in &fp.probes {
                for pattern in &probe.match_patterns {
                    if banner.contains(&pattern.pattern) {
                        return ServiceMatch {
                            service: pattern.service_name.clone(),
                            version: pattern.version_info.clone(),
                            confidence: 95,
                        };
                    }
                }
            }
        }

        fps.first().map(|f| ServiceMatch {
            service: f.service.clone(),
            version: String::new(),
            confidence: 50,
        }).unwrap_or(empty)
    }

    #[allow(dead_code)]
    pub fn identify_http(&self, response: &str) -> ServiceMatch {
        let patterns = [
            ("HTTP/1.", "http", "HTTP server"),
            ("Server: Apache", "http", "Apache"),
            ("Server: nginx", "http", "nginx"),
            ("Server: Microsoft-IIS", "http", "IIS"),
            ("Server: OpenSSH", "ssh", "OpenSSH"),
            ("SSH-2.0-", "ssh", "SSH v2"),
            ("SSH-1.", "ssh", "SSH v1"),
            ("220 ProFTPD", "ftp", "ProFTPD"),
            ("220 vsFTPd", "ftp", "vsFTPd"),
            ("220 Microsoft FTP", "ftp", "MS FTP"),
            ("530 Please login", "ftp", "FTP"),
            ("+OK POP3", "pop3", "POP3"),
            ("* OK IMAP4", "imap", "IMAP4"),
            ("220 smtp", "smtp", "SMTP"),
            ("220 ESMTP", "smtp", "ESMTP"),
            ("220 ", "smtp", "SMTP"),
            ("vN.NN", "vnc", "VNC"),
            ("RFB ", "vnc", "VNC"),
        ];

        for (pattern, service, version) in &patterns {
            if response.contains(pattern) {
                return ServiceMatch {
                    service: service.to_string(),
                    version: version.to_string(),
                    confidence: 90,
                };
            }
        }

        ServiceMatch {
            service: "unknown".to_string(),
            version: String::new(),
            confidence: 0,
        }
    }

    pub fn identify_udp_service(&self, port: u16, payload: &[u8]) -> ServiceMatch {
        let payload_str = String::from_utf8_lossy(payload);

        let udp_patterns: Vec<(u16, &str, &str)> = vec![
            (53, "domain", "DNS"),
            (67, "dhcps", "DHCP Server"),
            (68, "dhcpc", "DHCP Client"),
            (123, "ntp", "NTP"),
            (161, "snmp", "SNMP"),
            (162, "snmptrap", "SNMP Trap"),
            (500, "isakmp", "IKE"),
            (514, "syslog", "Syslog"),
            (1900, "ssdp", "SSDP"),
            (5353, "mdns", "mDNS"),
            (137, "netbios-ns", "NetBIOS NS"),
            (138, "netbios-dgm", "NetBIOS DGM"),
        ];

        for (p, svc, ver) in &udp_patterns {
            if port == *p {
                return ServiceMatch {
                    service: svc.to_string(),
                    version: ver.to_string(),
                    confidence: 80,
                };
            }
        }

        if payload_str.contains("HTTP/") {
            return ServiceMatch {
                service: "http".to_string(),
                version: "HTTP over UDP".to_string(),
                confidence: 85,
            };
        }

        ServiceMatch {
            service: "unknown".to_string(),
            version: String::new(),
            confidence: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMatch {
    pub service: String,
    pub version: String,
    pub confidence: u8,
}

fn build_default_fingerprints() -> Vec<ServiceFingerprint> {
    vec![
        ServiceFingerprint {
            port: 21,
            service: "ftp".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "220 ProFTPD".to_string(), service_name: "ftp".to_string(), version_info: "ProFTPD".to_string() },
                    MatchPattern { pattern: "220 vsFTPd".to_string(), service_name: "ftp".to_string(), version_info: "vsFTPd".to_string() },
                    MatchPattern { pattern: "220 ".to_string(), service_name: "ftp".to_string(), version_info: "FTP".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 22,
            service: "ssh".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "SSH-2.0-OpenSSH".to_string(), service_name: "ssh".to_string(), version_info: "OpenSSH".to_string() },
                    MatchPattern { pattern: "SSH-2.0-".to_string(), service_name: "ssh".to_string(), version_info: "SSH v2".to_string() },
                    MatchPattern { pattern: "SSH-1.".to_string(), service_name: "ssh".to_string(), version_info: "SSH v1".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 23,
            service: "telnet".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "\r\n".to_string(), service_name: "telnet".to_string(), version_info: "Telnet".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 25,
            service: "smtp".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "220 ESMTP".to_string(), service_name: "smtp".to_string(), version_info: "ESMTP".to_string() },
                    MatchPattern { pattern: "220 ".to_string(), service_name: "smtp".to_string(), version_info: "SMTP".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 53,
            service: "domain".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![],
        },
        ServiceFingerprint {
            port: 80,
            service: "http".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::HttpGet,
                data: "GET / HTTP/1.1\r\nHost: target\r\n\r\n".to_string(),
                match_patterns: vec![
                    MatchPattern { pattern: "Server: Apache".to_string(), service_name: "http".to_string(), version_info: "Apache".to_string() },
                    MatchPattern { pattern: "Server: nginx".to_string(), service_name: "http".to_string(), version_info: "nginx".to_string() },
                    MatchPattern { pattern: "Server: Microsoft-IIS".to_string(), service_name: "http".to_string(), version_info: "IIS".to_string() },
                    MatchPattern { pattern: "HTTP/1.".to_string(), service_name: "http".to_string(), version_info: "HTTP server".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 110,
            service: "pop3".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "+OK POP3".to_string(), service_name: "pop3".to_string(), version_info: "POP3".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 143,
            service: "imap".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "* OK IMAP4".to_string(), service_name: "imap".to_string(), version_info: "IMAP4".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 443,
            service: "https".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::SslHello,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "TLS".to_string(), service_name: "https".to_string(), version_info: "TLS".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 3306,
            service: "mysql".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "mysql".to_string(), service_name: "mysql".to_string(), version_info: "MySQL".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 3389,
            service: "ms-wbt-server".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "\x03".to_string(), service_name: "ms-wbt-server".to_string(), version_info: "RDP".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 5432,
            service: "postgresql".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "PostgreSQL".to_string(), service_name: "postgresql".to_string(), version_info: "PostgreSQL".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 6379,
            service: "redis".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "-NOAUTH".to_string(), service_name: "redis".to_string(), version_info: "Redis".to_string() },
                    MatchPattern { pattern: "-ERR".to_string(), service_name: "redis".to_string(), version_info: "Redis".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 8080,
            service: "http-proxy".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::HttpGet,
                data: "GET / HTTP/1.1\r\nHost: target\r\n\r\n".to_string(),
                match_patterns: vec![
                    MatchPattern { pattern: "HTTP/1.".to_string(), service_name: "http-proxy".to_string(), version_info: "HTTP Proxy".to_string() },
                ],
            }],
        },
        ServiceFingerprint {
            port: 27017,
            service: "mongodb".to_string(),
            protocol: "tcp".to_string(),
            probes: vec![Probe {
                probe_type: ProbeType::TcpBanner,
                data: String::new(),
                match_patterns: vec![
                    MatchPattern { pattern: "MongoDB".to_string(), service_name: "mongodb".to_string(), version_info: "MongoDB".to_string() },
                ],
            }],
        },
    ]
}
