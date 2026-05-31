use crate::cli::ProxyConfig;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone)]
pub struct ProxyChain {
    proxies: Vec<ProxyConfig>,
}

impl ProxyChain {
    pub fn new(proxies: Vec<ProxyConfig>) -> Self {
        ProxyChain { proxies }
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    pub fn connect(&self, target: &str, port: u16, timeout: Duration) -> Result<Box<dyn ProxyStream>, String> {
        if self.proxies.is_empty() {
            return Err("No proxies in chain".to_string());
        }

        let mut current_stream: Option<Box<dyn ProxyStream>> = None;

        for (i, proxy) in self.proxies.iter().enumerate() {
            let is_last = i == self.proxies.len() - 1;

            let (next_host, next_port) = if is_last {
                (target.to_string(), port)
            } else {
                (self.proxies[i + 1].host.clone(), self.proxies[i + 1].port)
            };

            match current_stream {
                None => {
                    let stream = connect_via_proxy(proxy, &next_host, next_port, timeout)?;
                    current_stream = Some(stream);
                }
                Some(mut stream) => {
                    stream = chain_via_proxy(stream, proxy, &next_host, next_port, timeout)?;
                    current_stream = Some(stream);
                }
            }
        }

        current_stream.ok_or_else(|| "Failed to establish proxy chain".to_string())
    }
}

pub trait ProxyStream: Read + Write + Send {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
    #[allow(dead_code)]
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
}

impl ProxyStream for std::net::TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        std::net::TcpStream::set_write_timeout(self, dur)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        std::net::TcpStream::peer_addr(self)
    }
}

fn connect_via_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<Box<dyn ProxyStream>, String> {
    match proxy.protocol.as_str() {
        "socks4" | "socks4a" => connect_socks4(proxy, target_host, target_port, timeout),
        "socks5" => connect_socks5(proxy, target_host, target_port, timeout),
        "http" | "https" => connect_http_proxy(proxy, target_host, target_port, timeout),
        _ => Err(format!("Unsupported proxy protocol: {}", proxy.protocol)),
    }
}

fn chain_via_proxy(
    stream: Box<dyn ProxyStream>,
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    _timeout: Duration,
) -> Result<Box<dyn ProxyStream>, String> {
    match proxy.protocol.as_str() {
        "socks4" | "socks4a" => socks4_handshake(stream, target_host, target_port, proxy),
        "socks5" => socks5_handshake(stream, target_host, target_port, proxy),
        "http" | "https" => http_proxy_handshake(stream, target_host, target_port, proxy),
        _ => Err(format!("Unsupported proxy protocol: {}", proxy.protocol)),
    }
}

fn connect_socks4(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<Box<dyn ProxyStream>, String> {
    let proxy_addr = format!("{}:{}", proxy.host, proxy.port)
        .parse::<SocketAddr>()
        .map_err(|e| format!("Invalid proxy address: {}", e))?;

    let stream = std::net::TcpStream::connect_timeout(&proxy_addr, timeout)
        .map_err(|e| format!("Failed to connect to proxy: {}", e))?;

    stream.set_read_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;
    stream.set_write_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    socks4_handshake(Box::new(stream), target_host, target_port, proxy)
}

fn socks4_handshake(
    mut stream: Box<dyn ProxyStream>,
    target_host: &str,
    target_port: u16,
    proxy: &ProxyConfig,
) -> Result<Box<dyn ProxyStream>, String> {
    use std::net::ToSocketAddrs;

    let target_ip = if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
        ip.octets()
    } else {
        let addr = format!("{}:0", target_host);
        match addr.to_socket_addrs().unwrap().next() {
            Some(SocketAddr::V4(v4)) => v4.ip().octets(),
            _ => return Err("Could not resolve target IPv4 for SOCKS4".to_string()),
        }
    };

    let userid = proxy.username.as_deref().unwrap_or("");

    let mut request = Vec::new();
    request.push(0x04);
    request.push(0x01);
    request.extend_from_slice(&target_port.to_be_bytes());
    request.extend_from_slice(&target_ip);
    request.extend_from_slice(userid.as_bytes());
    request.push(0x00);

    stream.write_all(&request)
        .map_err(|e| format!("Failed to send SOCKS4 request: {}", e))?;

    let mut response = [0u8; 8];
    stream.read_exact(&mut response)
        .map_err(|e| format!("Failed to read SOCKS4 response: {}", e))?;

    if response[1] != 0x5A {
        return Err(format!("SOCKS4 request rejected: code 0x{:02X}", response[1]));
    }

    Ok(stream)
}

fn connect_socks5(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<Box<dyn ProxyStream>, String> {
    let proxy_addr = format!("{}:{}", proxy.host, proxy.port)
        .parse::<SocketAddr>()
        .map_err(|e| format!("Invalid proxy address: {}", e))?;

    let stream = std::net::TcpStream::connect_timeout(&proxy_addr, timeout)
        .map_err(|e| format!("Failed to connect to proxy: {}", e))?;

    stream.set_read_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;
    stream.set_write_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    socks5_handshake(Box::new(stream), target_host, target_port, proxy)
}

fn socks5_handshake(
    mut stream: Box<dyn ProxyStream>,
    target_host: &str,
    target_port: u16,
    proxy: &ProxyConfig,
) -> Result<Box<dyn ProxyStream>, String> {
    let mut methods = vec![0x00];
    if proxy.username.is_some() {
        methods.push(0x02);
    }

    let mut hello = vec![0x05, methods.len() as u8];
    hello.extend(methods);
    stream.write_all(&hello)
        .map_err(|e| format!("Failed to send SOCKS5 hello: {}", e))?;

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp)
        .map_err(|e| format!("Failed to read SOCKS5 method: {}", e))?;

    if method_resp[0] != 0x05 {
        return Err("Invalid SOCKS5 response".to_string());
    }

    match method_resp[1] {
        0x00 => {}
        0x02 => {
            let username = proxy.username.as_deref().unwrap_or("");
            let password = proxy.password.as_deref().unwrap_or("");

            let mut auth = vec![0x01, username.len() as u8];
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());

            stream.write_all(&auth)
                .map_err(|e| format!("Failed to send SOCKS5 auth: {}", e))?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp)
                .map_err(|e| format!("Failed to read SOCKS5 auth resp: {}", e))?;

            if auth_resp[1] != 0x00 {
                return Err("SOCKS5 authentication failed".to_string());
            }
        }
        0xFF => return Err("No acceptable SOCKS5 auth method".to_string()),
        _ => return Err(format!("Unknown SOCKS5 method: 0x{:02X}", method_resp[1])),
    }

    let mut request = vec![0x05, 0x01, 0x00];

    if let Ok(ipv4) = target_host.parse::<std::net::Ipv4Addr>() {
        request.push(0x01);
        request.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target_host.parse::<std::net::Ipv6Addr>() {
        request.push(0x04);
        request.extend_from_slice(&ipv6.octets());
    } else {
        request.push(0x03);
        request.push(target_host.len() as u8);
        request.extend_from_slice(target_host.as_bytes());
    }

    request.extend_from_slice(&target_port.to_be_bytes());

    stream.write_all(&request)
        .map_err(|e| format!("Failed to send SOCKS5 connect: {}", e))?;

    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header)
        .map_err(|e| format!("Failed to read SOCKS5 connect resp: {}", e))?;

    if resp_header[1] != 0x00 {
        return Err(format!("SOCKS5 connect failed: code 0x{:02X}", resp_header[1]));
    }

    match resp_header[3] {
        0x01 => {
            let mut addr = [0u8; 6];
            stream.read_exact(&mut addr)
                .map_err(|e| format!("Failed to read SOCKS5 addr: {}", e))?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)
                .map_err(|e| format!("Failed to read SOCKS5 domain len: {}", e))?;
            let mut domain = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut domain)
                .map_err(|e| format!("Failed to read SOCKS5 domain: {}", e))?;
        }
        0x04 => {
            let mut addr = [0u8; 18];
            stream.read_exact(&mut addr)
                .map_err(|e| format!("Failed to read SOCKS5 ipv6: {}", e))?;
        }
        _ => return Err("Unknown SOCKS5 address type".to_string()),
    }

    Ok(stream)
}

fn connect_http_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<Box<dyn ProxyStream>, String> {
    let proxy_addr = format!("{}:{}", proxy.host, proxy.port)
        .parse::<SocketAddr>()
        .map_err(|e| format!("Invalid proxy address: {}", e))?;

    let stream = std::net::TcpStream::connect_timeout(&proxy_addr, timeout)
        .map_err(|e| format!("Failed to connect to proxy: {}", e))?;

    stream.set_read_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;
    stream.set_write_timeout(Some(timeout))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    http_proxy_handshake(Box::new(stream), target_host, target_port, proxy)
}

fn http_proxy_handshake(
    mut stream: Box<dyn ProxyStream>,
    target_host: &str,
    target_port: u16,
    proxy: &ProxyConfig,
) -> Result<Box<dyn ProxyStream>, String> {
    let connect_request = if let (Some(user), Some(pass)) = (&proxy.username, &proxy.password) {
        let auth = base64::encode(&format!("{}:{}", user, pass));
        format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
            target_host, target_port, target_host, target_port, auth
        )
    } else {
        format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
            target_host, target_port, target_host, target_port
        )
    };

    stream.write_all(connect_request.as_bytes())
        .map_err(|e| format!("Failed to send CONNECT: {}", e))?;

    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) => return Err(format!("Failed to read proxy response: {}", e)),
        }
    }

    let resp_str = String::from_utf8_lossy(&response);
    if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
        let first_line = resp_str.lines().next().unwrap_or("");
        return Err(format!("Proxy CONNECT failed: {}", first_line));
    }

    Ok(stream)
}

mod base64 {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut result = Vec::new();
        let mut i = 0;

        while i < bytes.len() {
            let b1 = bytes[i];
            let b2 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
            let b3 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };

            let idx1 = (b1 >> 2) as usize;
            let idx2 = (((b1 & 0x03) << 4) | ((b2 & 0xF0) >> 4)) as usize;
            let idx3 = (((b2 & 0x0F) << 2) | ((b3 & 0xC0) >> 6)) as usize;
            let idx4 = (b3 & 0x3F) as usize;

            result.push(CHARS[idx1]);
            result.push(CHARS[idx2]);

            if i + 1 < bytes.len() {
                result.push(CHARS[idx3]);
            } else {
                result.push(b'=');
            }

            if i + 2 < bytes.len() {
                result.push(CHARS[idx4]);
            } else {
                result.push(b'=');
            }

            i += 3;
        }

        String::from_utf8(result).unwrap_or_default()
    }
}
