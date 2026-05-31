use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "cli-nmap", version, about = "A simplified multi-protocol port scanner and service identifier")]
pub struct Cli {
    #[arg(help = "Target host (IP address or hostname)")]
    pub target: String,

    #[arg(short, long, default_value = "1-1024", help = "Port range, e.g. 1-1024 or 80,443,8080")]
    pub ports: String,

    #[arg(short = 't', long, default_value = "tcp", value_parser = ["tcp", "syn", "udp", "all"], help = "Scan type: tcp, syn, udp, all")]
    pub scan_type: String,

    #[arg(short, long, default_value_t = 100, help = "Number of concurrent threads")]
    pub threads: usize,

    #[arg(short, long, default_value_t = 3000, help = "Timeout per port in milliseconds")]
    pub timeout: u64,

    #[arg(short = 'o', long, default_value = "text", value_parser = ["text", "json"], help = "Output format: text or json")]
    pub output: String,

    #[arg(short = 'f', long, help = "Output file path (optional)")]
    pub file: Option<String>,

    #[arg(short = 'v', long, help = "Verbose output")]
    pub verbose: bool,
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
    All,
}

impl ScanType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "syn" => ScanType::TcpSyn,
            "udp" => ScanType::Udp,
            "all" => ScanType::All,
            _ => ScanType::TcpConnect,
        }
    }
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
