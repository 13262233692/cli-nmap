use crate::cli::{Cli, ScanType};
use crate::fingerprint::{FingerprintDB, ServiceMatch};
use crate::packet::{self, TcpResponse, UdpResponse};
use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::ip::IpAddr;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: String,
    pub version: String,
    pub confidence: u8,
    pub banner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

pub struct ScanEngine {
    target: String,
    ports: Vec<u16>,
    scan_types: Vec<ScanType>,
    threads: usize,
    timeout: Duration,
    verbose: bool,
    fingerprint_db: FingerprintDB,
}

impl ScanEngine {
    pub fn new(cli: &Cli) -> Self {
        let scan_types = match ScanType::from_str(&cli.scan_type) {
            ScanType::All => vec![ScanType::TcpConnect, ScanType::TcpSyn, ScanType::Udp],
            st => vec![st],
        };

        ScanEngine {
            target: cli.target.clone(),
            ports: crate::cli::parse_port_range(&cli.ports),
            scan_types,
            threads: cli.threads,
            timeout: Duration::from_millis(cli.timeout),
            verbose: cli.verbose,
            fingerprint_db: FingerprintDB::new(),
        }
    }

    pub fn run(&self) -> Vec<ScanResult> {
        let mut all_results = Vec::new();

        for scan_type in &self.scan_types {
            let results = match scan_type {
                ScanType::TcpConnect => self.tcp_connect_scan(),
                ScanType::TcpSyn => self.tcp_syn_scan(),
                ScanType::Udp => self.udp_scan(),
                ScanType::All => unreachable!(),
            };
            all_results.extend(results);
        }

        all_results.sort_by(|a, b| a.port.cmp(&b.port).then(a.protocol.cmp(&b.protocol)));
        all_results
    }

    fn resolve_target(&self) -> std::net::IpAddr {
        use std::net::ToSocketAddrs;
        let addr = format!("{}:0", self.target);
        match addr.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(a) = addrs.next() {
                    a.ip()
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                }
            }
            Err(_) => {
                eprintln!("Warning: Could not resolve '{}', using 127.0.0.1", self.target);
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            }
        }
    }

    fn tcp_connect_scan(&self) -> Vec<ScanResult> {
        let target_ip = self.resolve_target();
        let results = Arc::new(Mutex::new(Vec::new()));
        let ports = Arc::new(self.ports.clone());
        let timeout = self.timeout;
        let verbose = self.verbose;
        let target = self.target.clone();
        let fingerprint_db = Arc::new(FingerprintDB::new());

        let mut handles = Vec::new();
        let cores = self.threads.min(ports.len());
        let chunk_size = (ports.len() + cores - 1) / cores;

        for chunk in ports.chunks(chunk_size.max(1)) {
            let chunk = chunk.to_vec();
            let results = Arc::clone(&results);
            let target_ip = target_ip;
            let timeout = timeout;
            let verbose = verbose;
            let target = target.clone();
            let fingerprint_db = Arc::clone(&fingerprint_db);

            let handle = thread::spawn(move || {
                for port in chunk {
                    let addr = SocketAddr::new(target_ip, port);
                    let state = match TcpStream::connect_timeout(&addr, timeout) {
                        Ok(mut stream) => {
                            if verbose {
                                eprintln!("[+] TCP Connect: {}:{} OPEN", target, port);
                            }
                            PortState::Open
                        }
                        Err(e) => {
                            if verbose {
                                eprintln!("[-] TCP Connect: {}:{} closed/filtered ({})", target, port, e.kind());
                            }
                            PortState::Closed
                        }
                    };

                    let mut banner = String::new();
                    let service_match = if state == PortState::Open {
                        banner = grab_banner_tcp(target_ip, port, timeout);
                        if !banner.is_empty() {
                            fingerprint_db.identify_by_banner(&banner, port)
                        } else {
                            fingerprint_db.identify_by_port(port)
                                .map(|fp| ServiceMatch {
                                    service: fp.service.clone(),
                                    version: String::new(),
                                    confidence: 50,
                                })
                                .unwrap_or(ServiceMatch {
                                    service: "unknown".to_string(),
                                    version: String::new(),
                                    confidence: 0,
                                })
                        }
                    } else {
                        ServiceMatch {
                            service: String::new(),
                            version: String::new(),
                            confidence: 0,
                        }
                    };

                    let result = ScanResult {
                        host: target.clone(),
                        port,
                        protocol: "tcp".to_string(),
                        state,
                        service: service_match.service,
                        version: service_match.version,
                        confidence: service_match.confidence,
                        banner: banner.chars().take(256).collect(),
                    };

                    results.lock().unwrap().push(result);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut r = results.lock().unwrap().to_vec();
        r.retain(|r| r.state == PortState::Open);
        r
    }

    fn tcp_syn_scan(&self) -> Vec<ScanResult> {
        let target_ip = self.resolve_target();
        let results = Arc::new(Mutex::new(Vec::new()));
        let verbose = self.verbose;
        let target = self.target.clone();
        let fingerprint_db = Arc::new(FingerprintDB::new());

        let interface = match find_network_interface() {
            Some(iface) => iface,
            None => {
                eprintln!("Warning: No suitable network interface found for SYN scan, falling back to TCP Connect");
                return self.tcp_connect_scan();
            }
        };

        let src_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()) {
            Some(ip) => match ip.ip() {
                IpAddr::V4(ipv4) => ipv4,
                _ => {
                    eprintln!("Warning: No IPv4 address on interface, falling back to TCP Connect");
                    return self.tcp_connect_scan();
                }
            },
            None => {
                eprintln!("Warning: No IP on interface, falling back to TCP Connect");
                return self.tcp_connect_scan();
            }
        };

        let dst_ip = match target_ip {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => {
                eprintln!("Warning: SYN scan does not support IPv6, falling back to TCP Connect");
                return self.tcp_connect_scan();
            }
        };

        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => {
                eprintln!("Warning: Could not create data link channel, falling back to TCP Connect");
                return self.tcp_connect_scan();
            }
        };

        let dst_mac = get_gateway_mac(&interface, dst_ip);
        let src_mac = interface.mac_address.unwrap_or(MacAddr::new(0, 0, 0, 0, 0, 0));

        let response_ports: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let response_ports_clone = Arc::clone(&response_ports);
        let rx_timeout = self.timeout;

        let rx_handle = thread::spawn(move || {
            let deadline = std::time::Instant::now() + rx_timeout * 3;
            while std::time::Instant::now() < deadline {
                match rx.next_with_timeout(Duration::from_millis(100)) {
                    Ok(packet_data) => {
                        if let Some(tcp_resp) = packet::parse_tcp_response(packet_data) {
                            if tcp_resp.is_syn_ack {
                                let mut ports = response_ports_clone.lock().unwrap();
                                if !ports.contains(&tcp_resp.src_port) {
                                    ports.push(tcp_resp.src_port);
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        });

        for port in &self.ports {
            let src_port = packet::random_src_port();
            let syn_packet = packet::build_tcp_syn_packet(
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                src_port,
                *port,
            );
            if let Err(e) = tx.send_to(syn_packet.as_slice(), Some(interface.clone())) {
                if verbose {
                    eprintln!("Warning: Failed to send SYN packet to port {}: {:?}", port, e);
                }
            }
            if verbose {
                eprintln!("[*] SYN sent to {}:{} from port {}", target, port, src_port);
            }
        }

        rx_handle.join().unwrap();

        let open_ports = response_ports.lock().unwrap().clone();
        let mut scan_results = Vec::new();

        for port in &self.ports {
            let is_open = open_ports.contains(port);
            let state = if is_open {
                PortState::Open
            } else {
                PortState::Filtered
            };

            if state != PortState::Open && !verbose {
                continue;
            }

            let service_match = if is_open {
                fingerprint_db.identify_by_port(*port)
                    .map(|fp| ServiceMatch {
                        service: fp.service.clone(),
                        version: String::new(),
                        confidence: 50,
                    })
                    .unwrap_or(ServiceMatch {
                        service: "unknown".to_string(),
                        version: String::new(),
                        confidence: 0,
                    })
            } else {
                ServiceMatch {
                    service: String::new(),
                    version: String::new(),
                    confidence: 0,
                }
            };

            if is_open {
                let banner = grab_banner_tcp(target_ip, *port, self.timeout);
                let banner_match = if !banner.is_empty() {
                    fingerprint_db.identify_by_banner(&banner, *port)
                } else {
                    service_match.clone()
                };

                scan_results.push(ScanResult {
                    host: target.clone(),
                    port: *port,
                    protocol: "tcp".to_string(),
                    state: PortState::Open,
                    service: banner_match.service,
                    version: banner_match.version,
                    confidence: banner_match.confidence,
                    banner: banner.chars().take(256).collect(),
                });
            } else {
                scan_results.push(ScanResult {
                    host: target.clone(),
                    port: *port,
                    protocol: "tcp".to_string(),
                    state: PortState::Filtered,
                    service: String::new(),
                    version: String::new(),
                    confidence: 0,
                    banner: String::new(),
                });
            }
        }

        scan_results.retain(|r| r.state == PortState::Open);
        scan_results
    }

    fn udp_scan(&self) -> Vec<ScanResult> {
        let target_ip = self.resolve_target();
        let results = Arc::new(Mutex::new(Vec::new()));
        let verbose = self.verbose;
        let target = self.target.clone();
        let fingerprint_db = Arc::new(FingerprintDB::new());
        let timeout = self.timeout;

        let cores = self.threads.min(self.ports.len());
        let chunk_size = (self.ports.len() + cores - 1) / cores;

        let mut handles = Vec::new();

        for chunk in self.ports.chunks(chunk_size.max(1)) {
            let chunk = chunk.to_vec();
            let results = Arc::clone(&results);
            let target_ip = target_ip;
            let verbose = verbose;
            let target = target.clone();
            let fingerprint_db = Arc::clone(&fingerprint_db);
            let timeout = timeout;

            let handle = thread::spawn(move || {
                for port in chunk {
                    let bind_addr = "0.0.0.0:0";
                    let socket = match UdpSocket::bind(bind_addr) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    let _ = socket.set_read_timeout(Some(timeout));
                    let target_addr = SocketAddr::new(target_ip, port);

                    let probe_data = build_udp_probe(port);
                    if let Err(_) = socket.send_to(&probe_data, target_addr) {
                        if verbose {
                            eprintln!("[-] UDP: {}:{} send failed", target, port);
                        }
                        continue;
                    }

                    let mut buf = [0u8; 4096];
                    match socket.recv_from(&mut buf) {
                        Ok((len, _)) => {
                            let payload = &buf[..len];
                            let service_match = fingerprint_db.identify_udp_service(port, payload);
                            let banner = String::from_utf8_lossy(payload).to_string();

                            if verbose {
                                eprintln!("[+] UDP: {}:{} OPEN ({})", target, port, service_match.service);
                            }

                            results.lock().unwrap().push(ScanResult {
                                host: target.clone(),
                                port,
                                protocol: "udp".to_string(),
                                state: PortState::Open,
                                service: service_match.service,
                                version: service_match.version,
                                confidence: service_match.confidence,
                                banner: banner.chars().take(256).collect(),
                            });
                        }
                        Err(e) => {
                            let kind = e.kind();
                            if kind == std::io::ErrorKind::ConnectionRefused {
                                if verbose {
                                    eprintln!("[-] UDP: {}:{} closed (ICMP unreachable)", target, port);
                                }
                            } else if verbose {
                                eprintln!("[?] UDP: {}:{} open|filtered (no response)", target, port);
                            }

                            if verbose && kind != std::io::ErrorKind::ConnectionRefused {
                                let fp = fingerprint_db.identify_by_port(port);
                                results.lock().unwrap().push(ScanResult {
                                    host: target.clone(),
                                    port,
                                    protocol: "udp".to_string(),
                                    state: PortState::OpenFiltered,
                                    service: fp.map(|f| f.service.clone()).unwrap_or_default(),
                                    version: String::new(),
                                    confidence: 30,
                                    banner: String::new(),
                                });
                            }
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        results.lock().unwrap().to_vec()
    }
}

fn grab_banner_tcp(target: std::net::IpAddr, port: u16, timeout: Duration) -> String {
    let addr = SocketAddr::new(target, port);
    let mut banner = String::new();

    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) {
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        if port == 80 || port == 8080 || port == 443 || port == 8443 {
            let request = if port == 443 || port == 8443 {
                format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", target)
            } else {
                format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", target)
            };
            let _ = stream.write_all(request.as_bytes());
        }

        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(len) if len > 0 => {
                banner = String::from_utf8_lossy(&buf[..len]).to_string();
                let cleaned: String = banner.chars()
                    .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                    .collect();
                banner = cleaned;
            }
            _ => {}
        }
    }

    banner
}

fn build_udp_probe(port: u16) -> Vec<u8> {
    match port {
        53 => {
            let mut probe = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00];
            probe.extend_from_slice(b"\x07version\x04bind\x00\x00\x10\x00\x03");
            probe
        }
        123 => vec![0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        161 => vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70,
                     0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
                     0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00,
                     0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
                     0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00],
        _ => vec![0x00; 8],
    }
}

fn find_network_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    interfaces.into_iter().find(|iface| {
        iface.is_up()
            && !iface.is_loopback()
            && !iface.ips.is_empty()
            && iface.mac_address.is_some()
    })
}

fn get_gateway_mac(interface: &NetworkInterface, target: Ipv4Addr) -> MacAddr {
    interface.mac_address.unwrap_or(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff))
}
