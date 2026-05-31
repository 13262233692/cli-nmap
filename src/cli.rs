use clap::Parser;
use std::path::Path;

#[derive(Parser, Debug, Clone)]
#[command(name = "cli-nmap", version, about = "A simplified multi-protocol port scanner and service identifier")]
pub struct Cli {
    #[arg(help = "Target host (IP address or hostname)")]
    pub target: String,

    #[arg(short, long, default_value = "1-1024", help = "Port range, e.g. 1-1024 or 80,443,8080")]
    pub ports: String,

    #[arg(short = 'T', long, default_value = "tcp", value_parser = ["tcp", "syn", "udp", "zombie", "fin", "null", "xmas", "all"], help = "Scan type: tcp, syn, udp, zombie, fin, null, xmas, all")]
    pub scan_type: String,

    #[arg(short = 'n', long, default_value_t = 100, help = "Number of concurrent threads")]
    pub threads: usize,

    #[arg(short, long, default_value_t = 3000, help = "Timeout per port in milliseconds")]
    pub timeout: u64,

    #[arg(short = 'o', long, default_value = "text", value_parser = ["text", "json"], help = "Output format: text or json")]
    pub output: String,

    #[arg(short = 'f', long, help = "Output file path (optional)")]
    pub file: Option<String>,

    #[arg(short = 'v', long, help = "Verbose output")]
    pub verbose: bool,

    #[arg(long, default_value_t = 64, help = "Set custom TTL (Time To Live) for packets")]
    pub ttl: u8,

    #[arg(long, help = "Enable IP fragmentation with specified MTU size (e.g., --mtu 24 for 24-byte fragments)")]
    pub mtu: Option<u16>,

    #[arg(long, help = "Enable stealth scan mode (random delays, spoofed parameters)")]
    pub stealth: bool,

    #[arg(long, help = "Randomize scan order of ports for IDS evasion")]
    pub randomize_ports: bool,

    #[arg(long, help = "Specify zombie host for idle scan (e.g., 192.168.1.100)")]
    pub zombie: Option<String>,

    #[arg(long, help = "Zombie host port for idle scan (default: 80)")]
    pub zombie_port: Option<u16>,

    #[arg(long, help = "Source port for scanning (spoofed)")]
    pub source_port: Option<u16>,

    #[arg(long, help = "Send spoofed decoy IPs to hide real source (comma-separated)")]
    pub decoys: Option<String>,

    #[arg(long, help = "Path to proxy chain file (one proxy per line, format: proto://host:port)")]
    pub proxy_file: Option<String>,

    #[arg(long, help = "Delay between packets in milliseconds for stealth")]
    pub scan_delay: Option<u64>,
}

impl Cli {
    pub fn parse_args() -> Self {
        Parser::parse()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScanType {
    TcpConnect,
    TcpSyn,
    Udp,
    Fin,
    Null,
    Xmas,
    Zombie,
    All,
}

impl ScanType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "syn" => ScanType::TcpSyn,
            "udp" => ScanType::Udp,
            "fin" => ScanType::Fin,
            "null" => ScanType::Null,
            "xmas" => ScanType::Xmas,
            "zombie" => ScanType::Zombie,
            "all" => ScanType::All,
            _ => ScanType::TcpConnect,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub fn parse_port_range(input: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() == 2 {
                if let (Ok(start), Ok(end)) = (bounds[0].parse::<u16>(), bounds[1].parse::<u16>()) {
                    for p in start..=end {
                        ports.push(p);
                    }
                }
            }
        } else {
            if let Ok(p) = part.parse::<u16>() {
                ports.push(p);
            }
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

pub fn parse_proxy_file(path: &str) -> Result<Vec<ProxyConfig>, String> {
    let content = std::fs::read_to_string(Path::new(path))
        .map_err(|e| format!("Failed to read proxy file: {}", e))?;

    let mut proxies = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let proxy = parse_proxy_line(line)?;
        proxies.push(proxy);
    }

    if proxies.is_empty() {
        return Err("No valid proxies found in file".to_string());
    }

    Ok(proxies)
}

fn parse_proxy_line(line: &str) -> Result<ProxyConfig, String> {
    let mut parts = line.split("://");
    let protocol = parts.next().unwrap_or("socks5").to_lowercase();
    let rest = parts.next().ok_or_else(|| format!("Invalid proxy format: {}", line))?;

    let mut auth_parts = rest.split('@');
    let (auth, host_port) = if auth_parts.clone().count() > 1 {
        (Some(auth_parts.next().unwrap()), auth_parts.next().unwrap())
    } else {
        (None, rest)
    };

    let mut hp_parts = host_port.split(':');
    let host = hp_parts.next().ok_or_else(|| format!("Invalid proxy host: {}", line))?.to_string();
    let port = hp_parts.next()
        .ok_or_else(|| format!("Invalid proxy port: {}", line))?
        .parse::<u16>()
        .map_err(|e| format!("Invalid proxy port: {}", e))?;

    let (username, password) = if let Some(auth) = auth {
        let mut creds = auth.split(':');
        (
            creds.next().map(|s| s.to_string()),
            creds.next().map(|s| s.to_string()),
        )
    } else {
        (None, None)
    };

    Ok(ProxyConfig {
        protocol,
        host,
        port,
        username,
        password,
    })
}

pub fn parse_decoys(decoy_str: &str) -> Vec<String> {
    decoy_str.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range() {
        assert_eq!(parse_port_range("1-3"), vec![1, 2, 3]);
        assert_eq!(parse_port_range("1,2,3"), vec![1, 2, 3]);
        assert_eq!(parse_port_range("1-3,5,7-9"), vec![1, 2, 3, 5, 7, 8, 9]);
    }

    #[test]
    fn test_parse_proxy_line_socks5() {
        let p = parse_proxy_line("socks5://192.168.1.1:1080").unwrap();
        assert_eq!(p.protocol, "socks5");
        assert_eq!(p.host, "192.168.1.1");
        assert_eq!(p.port, 1080);
    }

    #[test]
    fn test_parse_proxy_line_with_auth() {
        let p = parse_proxy_line("http://user:pass@10.0.0.1:8080").unwrap();
        assert_eq!(p.protocol, "http");
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.username, Some("user".to_string()));
        assert_eq!(p.password, Some("pass".to_string()));
    }
}
