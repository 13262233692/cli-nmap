use crate::cli::{Cli, ScanType, parse_decoys, parse_proxy_file, ProxyConfig};
use crate::fingerprint::{FingerprintDB, ServiceMatch};
use crate::packet;
use crate::packet::{PacketOptions, TCP_FLAG_SYN, TCP_FLAG_FIN};
use crate::proxy::ProxyChain;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
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
    Unfiltered,
}

pub struct ScanEngine {
    target: String,
    ports: Vec<u16>,
    scan_types: Vec<ScanType>,
    threads: usize,
    timeout: Duration,
    verbose: bool,
    ttl: u8,
    mtu: Option<u16>,
    stealth: bool,
    #[allow(dead_code)]
    randomize_ports: bool,
    zombie_host: Option<String>,
    zombie_port: u16,
    source_port: Option<u16>,
    decoys: Vec<String>,
    proxy_chain: Option<Vec<ProxyConfig>>,
    scan_delay: Option<Duration>,
}

impl ScanEngine {
    pub fn new(cli: &Cli) -> Self {
        let scan_types = match ScanType::from_str(&cli.scan_type) {
            ScanType::All => vec![ScanType::TcpConnect, ScanType::TcpSyn, ScanType::Udp],
            st => vec![st],
        };

        let mut ports = crate::cli::parse_port_range(&cli.ports);
        let randomize = cli.randomize_ports || cli.stealth;
        if randomize {
            let mut rng = rand::thread_rng();
            ports.shuffle(&mut rng);
        }

        let proxy_chain = cli.proxy_file.as_ref().and_then(|path| {
            match parse_proxy_file(path) {
                Ok(proxies) => {
                    eprintln!("Loaded {} proxies from chain file", proxies.len());
                    Some(proxies)
                }
                Err(e) => {
                    eprintln!("Warning: {}", e);
                    None
                }
            }
        });

        let decoys = cli.decoys.as_ref()
            .map(|d| parse_decoys(d))
            .unwrap_or_default();

        let scan_delay = if cli.stealth && cli.scan_delay.is_none() {
            Some(Duration::from_millis(100))
        } else {
            cli.scan_delay.map(Duration::from_millis)
        };

        ScanEngine {
            target: cli.target.clone(),
            ports,
            scan_types,
            threads: cli.threads,
            timeout: Duration::from_millis(cli.timeout),
            verbose: cli.verbose,
            ttl: cli.ttl,
            mtu: cli.mtu,
            stealth: cli.stealth,
            randomize_ports: randomize,
            zombie_host: cli.zombie.clone(),
            zombie_port: cli.zombie_port.unwrap_or(80),
            source_port: cli.source_port,
            decoys,
            proxy_chain,
            scan_delay,
        }
    }

    pub fn run(&self) -> Vec<ScanResult> {
        let mut all_results = Vec::new();

        for scan_type in &self.scan_types {
            let results = match scan_type {
                ScanType::TcpConnect => self.tcp_connect_scan(),
                ScanType::TcpSyn => self.tcp_syn_scan(),
                ScanType::Udp => self.udp_scan(),
                ScanType::Fin => self.tcp_fin_scan(),
                ScanType::Null => self.tcp_null_scan(),
                ScanType::Xmas => self.tcp_xmas_scan(),
                ScanType::Zombie => self.zombie_scan(),
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

    fn resolve_host(&self, host: &str) -> std::net::IpAddr {
        use std::net::ToSocketAddrs;
        let addr = format!("{}:0", host);
        match addr.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(a) = addrs.next() {
                    a.ip()
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                }
            }
            Err(_) => {
                eprintln!("Warning: Could not resolve '{}', using 127.0.0.1", host);
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            }
        }
    }

    fn get_local_ipv4(&self) -> Option<Ipv4Addr> {
        let target_ip = self.resolve_target();
        match target_ip {
            std::net::IpAddr::V4(ipv4) => {
                let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
                socket.connect(SocketAddrV4::new(ipv4, 1)).ok()?;
                let local = socket.local_addr().ok()?;
                match local.ip() {
                    std::net::IpAddr::V4(local_ipv4) => Some(local_ipv4),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn get_packet_options(&self, flags: Option<u8>) -> PacketOptions {
        PacketOptions {
            ttl: self.ttl,
            mtu: self.mtu,
            source_port: self.source_port,
            decoys: self.decoys.clone(),
            tcp_flags: flags,
        }
    }

    fn apply_delay(&self) {
        if let Some(delay) = self.scan_delay {
            thread::sleep(delay);
        }
    }

    fn send_with_fragments_and_decoys(
        &self,
        socket: &Socket,
        base_packet: Vec<u8>,
        target_port: u16,
        dst_addr: &SockAddr,
        verbose_prefix: &str,
    ) -> std::io::Result<()> {
        let mut all_packets = Vec::new();

        if let Some(mtu) = self.mtu {
            let fragments = packet::fragment_packet(&base_packet, mtu);
            if self.verbose {
                eprintln!("[*] {} Fragmented into {} pieces", verbose_prefix, fragments.len());
            }
            all_packets.extend(fragments);
        } else {
            all_packets.push(base_packet.clone());
        }

        if !self.decoys.is_empty() {
            let decoy_packets = packet::generate_decoy_packets(&base_packet, &self.decoys, target_port);
            if self.verbose {
                eprintln!("[*] {} Generated {} decoy packets", verbose_prefix, decoy_packets.len());
            }
            all_packets.extend(decoy_packets);
        }

        if self.stealth {
            packet::shuffle_packets(&mut all_packets);
        }

        for pkt in all_packets {
            socket.send_to(&pkt, dst_addr)?;
            self.apply_delay();
        }

        Ok(())
    }

    fn tcp_connect_scan(&self) -> Vec<ScanResult> {
        let target_ip = self.resolve_target();
        let results = Arc::new(Mutex::new(Vec::new()));
        let fingerprint_db = Arc::new(FingerprintDB::new());
        let proxy_chain = self.proxy_chain.clone().map(ProxyChain::new);

        let mut handles = Vec::new();
        let ports = self.ports.clone();
        let cores = self.threads.min(ports.len());
        let chunk_size = (ports.len() + cores - 1) / cores;

        for chunk in ports.chunks(chunk_size.max(1)) {
            let chunk = chunk.to_vec();
            let results = Arc::clone(&results);
            let target_ip = target_ip;
            let timeout = self.timeout;
            let verbose = self.verbose;
            let target = self.target.clone();
            let fingerprint_db = Arc::clone(&fingerprint_db);
            let proxy_chain = proxy_chain.clone();
            let scan_delay = self.scan_delay;

            let handle = thread::spawn(move || {
                for port in chunk {
                    if let Some(delay) = scan_delay {
                        thread::sleep(delay);
                    }

                    let addr = SocketAddr::new(target_ip, port);

                    let stream_result = if let Some(chain) = &proxy_chain {
                        chain.connect(&target, port, timeout)
                            .map(|s| {
                                let _ = s.set_read_timeout(Some(timeout));
                                let _ = s.set_write_timeout(Some(timeout));
                                s
                            })
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                    } else {
                        TcpStream::connect_timeout(&addr, timeout)
                            .map(|s| {
                                let _ = s.set_read_timeout(Some(timeout));
                                let _ = s.set_write_timeout(Some(timeout));
                                s
                            })
                            .map(|s| Box::new(s) as Box<dyn crate::proxy::ProxyStream>)
                    };

                    let state = match stream_result {
                        Ok(_stream) => {
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
                        banner = grab_banner_tcp_generic(target_ip, port, timeout, &proxy_chain, &target);
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
        self.raw_tcp_scan_with_flags(TCP_FLAG_SYN, "SYN")
    }

    fn tcp_fin_scan(&self) -> Vec<ScanResult> {
        self.raw_tcp_scan_with_flags(TCP_FLAG_FIN, "FIN")
    }

    fn tcp_null_scan(&self) -> Vec<ScanResult> {
        self.raw_tcp_scan_with_flags(0, "NULL")
    }

    fn tcp_xmas_scan(&self) -> Vec<ScanResult> {
        let flags = packet::TCP_FLAG_FIN | packet::TCP_FLAG_URG | packet::TCP_FLAG_PSH;
        self.raw_tcp_scan_with_flags(flags, "XMAS")
    }

    fn raw_tcp_scan_with_flags(&self, flags: u8, scan_name: &str) -> Vec<ScanResult> {
        let target_ip = self.resolve_target();
        let verbose = self.verbose;
        let target = self.target.clone();
        let fingerprint_db = Arc::new(FingerprintDB::new());

        let dst_ip = match target_ip {
            std::net::IpAddr::V4(ipv4) => ipv4,
            std::net::IpAddr::V6(_) => {
                eprintln!("Warning: {} scan does not support IPv6, falling back to TCP Connect", scan_name);
                return self.tcp_connect_scan();
            }
        };

        let src_ip = match self.get_local_ipv4() {
            Some(ip) => ip,
            None => {
                eprintln!("Warning: Could not determine local IPv4, falling back to TCP Connect");
                return self.tcp_connect_scan();
            }
        };

        let src_ip_bytes = src_ip.octets();
        let dst_ip_bytes = dst_ip.octets();

        let send_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6))) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: Cannot create raw socket ({}). Falling back to TCP Connect.", e);
                eprintln!("  Hint: {} scan requires administrator/root privileges.", scan_name);
                return self.tcp_connect_scan();
            }
        };

        let mut recv_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6))) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: Cannot create raw recv socket ({}). Falling back to TCP Connect.", e);
                return self.tcp_connect_scan();
            }
        };

        if let Err(e) = recv_socket.set_read_timeout(Some(Duration::from_millis(200))) {
            eprintln!("Warning: Failed to set recv timeout: {}", e);
        }

        if let Err(e) = send_socket.set_header_included_v4(true) {
            eprintln!("Warning: Failed to set header included: {}", e);
        }

        if let Err(e) = send_socket.set_ttl(self.ttl as u32) {
            eprintln!("Warning: Failed to set TTL: {}", e);
        }

        let response_ports: Arc<Mutex<Vec<(u16, PortState)>>> = Arc::new(Mutex::new(Vec::new()));
        let response_ports_clone = Arc::clone(&response_ports);
        let rx_timeout = self.timeout;

        let scan_name_for_thread = scan_name.to_string();
        let rx_handle = thread::spawn(move || {
            let deadline = std::time::Instant::now() + rx_timeout * 3;
            let mut buf = [0u8; 65535];
            while std::time::Instant::now() < deadline {
                match recv_socket.read(&mut buf) {
                    Ok(len) => {
                        if let Some(tcp_resp) = packet::parse_tcp_response(&buf[..len]) {
                            let state = if scan_name_for_thread == "SYN" {
                                if tcp_resp.is_syn_ack {
                                    Some(PortState::Open)
                                } else if tcp_resp.is_rst {
                                    Some(PortState::Closed)
                                } else {
                                    None
                                }
                            } else {
                                if tcp_resp.is_rst {
                                    Some(PortState::Closed)
                                } else {
                                    Some(PortState::OpenFiltered)
                                }
                            };

                            if let Some(s) = state {
                                let mut ports = response_ports_clone.lock().unwrap();
                                if !ports.iter().any(|(p, _)| *p == tcp_resp.src_port) {
                                    ports.push((tcp_resp.src_port, s));
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        });

        let options = self.get_packet_options(Some(flags));
        let dst_addr = SockAddr::from(SocketAddrV4::new(dst_ip, 0));
        for port in &self.ports {
            let src_port = self.source_port.unwrap_or_else(packet::random_src_port);
            let syn_packet = packet::build_tcp_syn_packet_with_options(
                src_ip_bytes,
                dst_ip_bytes,
                src_port,
                *port,
                &options,
            );

            let prefix = format!("[{}]", scan_name);
            if let Err(e) = self.send_with_fragments_and_decoys(
                &send_socket,
                syn_packet,
                *port,
                &dst_addr,
                &prefix,
            ) {
                if verbose {
                    eprintln!("Warning: Failed to send {} packet to port {}: {:?}", scan_name, port, e);
                }
            }
            if verbose {
                eprintln!("[*] {} sent to {}:{} from port {}", scan_name, target, port, src_port);
            }
            self.apply_delay();
        }

        rx_handle.join().unwrap();

        let responses = response_ports.lock().unwrap().clone();
        let mut scan_results = Vec::new();

        for port in &self.ports {
            let found = responses.iter().find(|(p, _)| p == port);

            let state = match found {
                Some((_, s)) => s.clone(),
                None => {
                    if scan_name == "SYN" {
                        PortState::Filtered
                    } else {
                        PortState::OpenFiltered
                    }
                }
            };

            if state == PortState::Open || state == PortState::OpenFiltered || verbose {
                let mut banner = String::new();
                let service_match = if state == PortState::Open {
                    banner = grab_banner_tcp(target_ip, *port, self.timeout);
                    if !banner.is_empty() {
                        fingerprint_db.identify_by_banner(&banner, *port)
                    } else {
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
                    }
                } else {
                    fingerprint_db.identify_by_port(*port)
                        .map(|fp| ServiceMatch {
                            service: fp.service.clone(),
                            version: String::new(),
                            confidence: 30,
                        })
                        .unwrap_or(ServiceMatch {
                            service: String::new(),
                            version: String::new(),
                            confidence: 0,
                        })
                };

                if verbose {
                    eprintln!("[+] {}: {}:{} {:?}", scan_name, target, port, state);
                }

                scan_results.push(ScanResult {
                    host: target.clone(),
                    port: *port,
                    protocol: "tcp".to_string(),
                    state,
                    service: service_match.service,
                    version: service_match.version,
                    confidence: service_match.confidence,
                    banner: banner.chars().take(256).collect(),
                });
            }
        }

        scan_results.retain(|r| {
            r.state == PortState::Open
                || r.state == PortState::OpenFiltered
                || (verbose && (r.state == PortState::Filtered || r.state == PortState::Closed))
        });
        scan_results
    }

    fn zombie_scan(&self) -> Vec<ScanResult> {
        let verbose = self.verbose;
        let target = self.target.clone();
        let fingerprint_db = Arc::new(FingerprintDB::new());

        let zombie_host = match &self.zombie_host {
            Some(h) => h.clone(),
            None => {
                eprintln!("Error: Zombie host not specified. Use --zombie <host>");
                return Vec::new();
            }
        };

        let zombie_port = self.zombie_port;

        eprintln!("[*] Starting zombie scan with zombie: {}:{}", zombie_host, zombie_port);
        eprintln!("[*] Step 1: Probing zombie host IP ID sequence...");

        let zombie_ip = match self.resolve_host(&zombie_host) {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => {
                eprintln!("Error: Zombie host must be IPv4");
                return Vec::new();
            }
        };

        let target_ip = match self.resolve_target() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => {
                eprintln!("Error: Target must be IPv4 for zombie scan");
                return Vec::new();
            }
        };

        let src_ip = match self.get_local_ipv4() {
            Some(ip) => ip,
            None => {
                eprintln!("Error: Could not determine local IPv4");
                return Vec::new();
            }
        };

        let src_ip_bytes = src_ip.octets();
        let zombie_ip_bytes = zombie_ip.octets();
        let target_ip_bytes = target_ip.octets();

        let send_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6))) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error: Cannot create raw socket ({}). Requires admin/root.", e);
                return Vec::new();
            }
        };

        let mut recv_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6))) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error: Cannot create raw recv socket: {}", e);
                return Vec::new();
            }
        };

        if let Err(e) = send_socket.set_header_included_v4(true) {
            eprintln!("Warning: Failed to set header included: {}", e);
        }

        if let Err(e) = recv_socket.set_read_timeout(Some(Duration::from_millis(300))) {
            eprintln!("Warning: Failed to set recv timeout: {}", e);
        }

        let initial_id = match get_zombie_ip_id(
            &send_socket,
            &mut recv_socket,
            src_ip_bytes,
            zombie_ip_bytes,
            zombie_port,
            &self.get_packet_options(None),
        ) {
            Some(id) => id,
            None => {
                eprintln!("Error: Could not get initial IP ID from zombie. Zombie may not be suitable.");
                return Vec::new();
            }
        };

        eprintln!("[*] Zombie initial IP ID: 0x{:04X}", initial_id);
        eprintln!("[*] Step 2: Spoofing SYN packets from zombie to target...");

        let target_addr = SockAddr::from(SocketAddrV4::new(target_ip, 0));
        let options = self.get_packet_options(Some(TCP_FLAG_SYN));

        for port in &self.ports {
            let spoofed_packet = packet::build_tcp_syn_packet_with_options(
                zombie_ip_bytes,
                target_ip_bytes,
                packet::random_src_port(),
                *port,
                &options,
            );

            if let Err(e) = send_socket.send_to(&spoofed_packet, &target_addr) {
                if verbose {
                    eprintln!("Warning: Failed to send spoofed SYN to target port {}: {:?}", port, e);
                }
            }
            self.apply_delay();

            if verbose {
                eprintln!("[*] Spoofed SYN from zombie to target:{}", port);
            }
        }

        thread::sleep(Duration::from_millis(500));

        eprintln!("[*] Step 3: Probing zombie IP ID after scan...");

        let final_id = match get_zombie_ip_id(
            &send_socket,
            &mut recv_socket,
            src_ip_bytes,
            zombie_ip_bytes,
            zombie_port,
            &options,
        ) {
            Some(id) => id,
            None => {
                eprintln!("Error: Could not get final IP ID from zombie.");
                return Vec::new();
            }
        };

        eprintln!("[*] Zombie final IP ID: 0x{:04X}", final_id);

        let ip_id_delta = final_id.wrapping_sub(initial_id);
        eprintln!("[*] IP ID delta: {}", ip_id_delta);

        let mut results = Vec::new();
        if ip_id_delta >= 2 {
            eprintln!("[+] Detected open ports based on IP ID increment of {}", ip_id_delta);
            for port in &self.ports {
                if verbose {
                    eprintln!("[*] Port {}: attempting detailed verification...", port);
                }
                let individual_id_before = match get_zombie_ip_id(
                    &send_socket,
                    &mut recv_socket,
                    src_ip_bytes,
                    zombie_ip_bytes,
                    zombie_port,
                    &options,
                ) {
                    Some(id) => id,
                    None => continue,
                };

                let spoofed_packet = packet::build_tcp_syn_packet_with_options(
                    zombie_ip_bytes,
                    target_ip_bytes,
                    packet::random_src_port(),
                    *port,
                    &options,
                );
                let _ = send_socket.send_to(&spoofed_packet, &target_addr);
                thread::sleep(Duration::from_millis(200));

                let individual_id_after = match get_zombie_ip_id(
                    &send_socket,
                    &mut recv_socket,
                    src_ip_bytes,
                    zombie_ip_bytes,
                    zombie_port,
                    &options,
                ) {
                    Some(id) => id,
                    None => continue,
                };

                let individual_delta = individual_id_after.wrapping_sub(individual_id_before);
                let is_open = individual_delta >= 2;

                let state = if is_open {
                    PortState::Open
                } else {
                    PortState::Closed
                };

                let service_match = if is_open {
                    fingerprint_db.identify_by_port(*port)
                        .map(|fp| ServiceMatch {
                            service: fp.service.clone(),
                            version: String::new(),
                            confidence: 70,
                        })
                        .unwrap_or(ServiceMatch {
                            service: "unknown".to_string(),
                            version: String::new(),
                            confidence: 40,
                        })
                } else {
                    ServiceMatch {
                        service: String::new(),
                        version: String::new(),
                        confidence: 0,
                    }
                };

                if is_open || verbose {
                    eprintln!("[+] Zombie: {}:{} {:?} (ID delta: {})", target, port, state, individual_delta);
                    results.push(ScanResult {
                        host: target.clone(),
                        port: *port,
                        protocol: "tcp".to_string(),
                        state,
                        service: service_match.service,
                        version: service_match.version,
                        confidence: service_match.confidence,
                        banner: format!("IP ID delta: {}", individual_delta),
                    });
                }
            }
        } else {
            eprintln!("[-] No ports appear open (IP ID delta: {} < 2)", ip_id_delta);
            eprintln!("[*] Note: Zombie host may not be idle or may not use incremental IP IDs");
        }

        results.retain(|r| r.state == PortState::Open || verbose);
        results
    }

    fn udp_scan(&self) -> Vec<ScanResult> {
        let target_ip = self.resolve_target();
        let results = Arc::new(Mutex::new(Vec::new()));
        let fingerprint_db = Arc::new(FingerprintDB::new());

        let cores = self.threads.min(self.ports.len());
        let chunk_size = (self.ports.len() + cores - 1) / cores;

        let mut handles = Vec::new();

        for chunk in self.ports.chunks(chunk_size.max(1)) {
            let chunk = chunk.to_vec();
            let results = Arc::clone(&results);
            let target_ip = target_ip;
            let verbose = self.verbose;
            let target = self.target.clone();
            let fingerprint_db = Arc::clone(&fingerprint_db);
            let timeout = self.timeout;
            let scan_delay = self.scan_delay;

            let handle = thread::spawn(move || {
                for port in chunk {
                    if let Some(delay) = scan_delay {
                        thread::sleep(delay);
                    }

                    let socket = match UdpSocket::bind("0.0.0.0:0") {
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

        let res = results.lock().unwrap().to_vec();
        res
    }
}

fn get_zombie_ip_id(
    send_socket: &Socket,
    recv_socket: &mut Socket,
    src_ip: [u8; 4],
    zombie_ip: [u8; 4],
    zombie_port: u16,
    options: &PacketOptions,
) -> Option<u16> {
    let zombie_addr = SockAddr::from(SocketAddrV4::new(Ipv4Addr::from(zombie_ip), 0));
    let mut last_id = None;

    for _attempt in 0..3 {
        let src_port = packet::random_src_port();
        let syn_packet = packet::build_tcp_syn_packet_with_options(
            src_ip,
            zombie_ip,
            src_port,
            zombie_port,
            options,
        );

        if send_socket.send_to(&syn_packet, &zombie_addr).is_err() {
            thread::sleep(Duration::from_millis(100));
            continue;
        }

        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        let mut buf = [0u8; 65535];

        while std::time::Instant::now() < deadline {
            match recv_socket.read(&mut buf) {
                Ok(len) => {
                    if let Some(ip_header) = packet::parse_ip_header(&buf[..len]) {
                        if ip_header.src_ip == zombie_ip
                            && ip_header.protocol == 6
                        {
                            if let Some(tcp_resp) = packet::parse_tcp_response(&buf[..len]) {
                                if tcp_resp.dst_port == src_port
                                    && (tcp_resp.is_rst || tcp_resp.is_syn_ack)
                                {
                                    last_id = Some(ip_header.id);
                                    return last_id;
                                }
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    last_id
}

fn grab_banner_tcp(target: std::net::IpAddr, port: u16, timeout: Duration) -> String {
    grab_banner_tcp_generic(target, port, timeout, &None, "")
}

fn grab_banner_tcp_generic(
    target: std::net::IpAddr,
    port: u16,
    timeout: Duration,
    proxy_chain: &Option<ProxyChain>,
    target_host: &str,
) -> String {
    let mut banner = String::new();

    let stream_result = if let Some(chain) = proxy_chain {
        chain.connect(target_host, port, timeout)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    } else {
        let addr = SocketAddr::new(target, port);
        TcpStream::connect_timeout(&addr, timeout)
            .map(|s| Box::new(s) as Box<dyn crate::proxy::ProxyStream>)
    };

    if let Ok(mut stream) = stream_result {
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        if port == 80 || port == 8080 || port == 443 || port == 8443 {
            let host = if target_host.is_empty() { target.to_string() } else { target_host.to_string() };
            let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
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
