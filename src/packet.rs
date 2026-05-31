use rand::seq::SliceRandom;
use rand::Rng;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;
#[allow(dead_code)]
pub const TCP_FLAG_ECE: u8 = 0x40;
#[allow(dead_code)]
pub const TCP_FLAG_CWR: u8 = 0x80;

pub struct PacketOptions {
    pub ttl: u8,
    pub mtu: Option<u16>,
    pub source_port: Option<u16>,
    #[allow(dead_code)]
    pub decoys: Vec<String>,
    pub tcp_flags: Option<u8>,
}

impl Default for PacketOptions {
    fn default() -> Self {
        PacketOptions {
            ttl: 64,
            mtu: None,
            source_port: None,
            decoys: Vec::new(),
            tcp_flags: None,
        }
    }
}

pub fn build_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    options: &PacketOptions,
) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + TCP_HEADER_LEN;
    let mut buf = vec![0u8; total_len];
    let mut rng = rand::thread_rng();

    buf[0] = 0x45;
    buf[1] = 0x00;
    let total_len_be = (total_len as u16).to_be_bytes();
    buf[2] = total_len_be[0];
    buf[3] = total_len_be[1];
    let id: u16 = rng.gen();
    buf[4] = (id >> 8) as u8;
    buf[5] = (id & 0xFF) as u8;

    if let Some(mtu) = options.mtu {
        let frag_offset = 0u16;
        let flags_and_frag = (frag_offset & 0x1FFF) | 0x2000;
        buf[6] = (flags_and_frag >> 8) as u8;
        buf[7] = (flags_and_frag & 0xFF) as u8;
        let _ = mtu;
    } else {
        buf[6] = 0x40;
        buf[7] = 0x00;
    }

    buf[8] = options.ttl;
    buf[9] = 6;
    buf[10] = 0;
    buf[11] = 0;
    buf[12] = src_ip[0];
    buf[13] = src_ip[1];
    buf[14] = src_ip[2];
    buf[15] = src_ip[3];
    buf[16] = dst_ip[0];
    buf[17] = dst_ip[1];
    buf[18] = dst_ip[2];
    buf[19] = dst_ip[3];

    let ip_checksum = compute_checksum(&buf[0..20]);
    buf[10] = (ip_checksum >> 8) as u8;
    buf[11] = (ip_checksum & 0xFF) as u8;

    let tcp_offset = 20;
    let actual_src_port = options.source_port.unwrap_or(src_port);
    let src_port_be = actual_src_port.to_be_bytes();
    buf[tcp_offset] = src_port_be[0];
    buf[tcp_offset + 1] = src_port_be[1];
    let dst_port_be = dst_port.to_be_bytes();
    buf[tcp_offset + 2] = dst_port_be[0];
    buf[tcp_offset + 3] = dst_port_be[1];

    let seq: u32 = rng.gen();
    buf[tcp_offset + 4] = (seq >> 24) as u8;
    buf[tcp_offset + 5] = (seq >> 16) as u8;
    buf[tcp_offset + 6] = (seq >> 8) as u8;
    buf[tcp_offset + 7] = (seq & 0xFF) as u8;

    let ack: u32 = if flags & TCP_FLAG_ACK != 0 {
        rng.gen()
    } else {
        0
    };
    buf[tcp_offset + 8] = (ack >> 24) as u8;
    buf[tcp_offset + 9] = (ack >> 16) as u8;
    buf[tcp_offset + 10] = (ack >> 8) as u8;
    buf[tcp_offset + 11] = (ack & 0xFF) as u8;

    buf[tcp_offset + 12] = 0x50;
    buf[tcp_offset + 13] = flags;

    buf[tcp_offset + 14] = 0xFF;
    buf[tcp_offset + 15] = 0x1F;

    buf[tcp_offset + 16] = 0;
    buf[tcp_offset + 17] = 0;
    buf[tcp_offset + 18] = 0;
    buf[tcp_offset + 19] = 0;

    let tcp_checksum = compute_tcp_checksum(src_ip, dst_ip, &buf[tcp_offset..]);
    buf[tcp_offset + 16] = (tcp_checksum >> 8) as u8;
    buf[tcp_offset + 17] = (tcp_checksum & 0xFF) as u8;

    buf
}

#[allow(dead_code)]
pub fn build_tcp_syn_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    build_tcp_packet(src_ip, dst_ip, src_port, dst_port, TCP_FLAG_SYN, &PacketOptions::default())
}

pub fn build_tcp_syn_packet_with_options(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    options: &PacketOptions,
) -> Vec<u8> {
    let flags = options.tcp_flags.unwrap_or(TCP_FLAG_SYN);
    build_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags, options)
}

#[allow(dead_code)]
pub fn build_tcp_fin_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    options: &PacketOptions,
) -> Vec<u8> {
    build_tcp_packet(src_ip, dst_ip, src_port, dst_port, TCP_FLAG_FIN, options)
}

#[allow(dead_code)]
pub fn build_tcp_null_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    options: &PacketOptions,
) -> Vec<u8> {
    build_tcp_packet(src_ip, dst_ip, src_port, dst_port, 0, options)
}

#[allow(dead_code)]
pub fn build_tcp_xmas_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    options: &PacketOptions,
) -> Vec<u8> {
    let flags = TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH;
    build_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags, options)
}

pub fn fragment_packet(packet: &[u8], mtu: u16) -> Vec<Vec<u8>> {
    if packet.len() <= mtu as usize {
        return vec![packet.to_vec()];
    }

    let mut fragments = Vec::new();
    let payload_start = IPV4_HEADER_LEN;
    let header = &packet[0..payload_start];
    let payload = &packet[payload_start..];

    let max_payload = (mtu as usize - IPV4_HEADER_LEN) & !7;
    let mut offset = 0usize;
    let mut id: u16 = rand::thread_rng().gen();

    while offset < payload.len() {
        let chunk_size = max_payload.min(payload.len() - offset);
        let is_last = offset + chunk_size >= payload.len();

        let mut frag = vec![0u8; IPV4_HEADER_LEN + chunk_size];
        frag[0..IPV4_HEADER_LEN].copy_from_slice(header);

        id = id.wrapping_add(1);
        frag[4] = (id >> 8) as u8;
        frag[5] = (id & 0xFF) as u8;

        let frag_offset_bits = (offset / 8) as u16;
        let flags_and_frag = if is_last {
            frag_offset_bits
        } else {
            frag_offset_bits | 0x2000
        };
        frag[6] = (flags_and_frag >> 8) as u8;
        frag[7] = (flags_and_frag & 0xFF) as u8;

        let total_len = (IPV4_HEADER_LEN + chunk_size) as u16;
        let total_len_be = total_len.to_be_bytes();
        frag[2] = total_len_be[0];
        frag[3] = total_len_be[1];

        frag[10] = 0;
        frag[11] = 0;
        let checksum = compute_checksum(&frag[0..20]);
        frag[10] = (checksum >> 8) as u8;
        frag[11] = (checksum & 0xFF) as u8;

        frag[IPV4_HEADER_LEN..IPV4_HEADER_LEN + chunk_size]
            .copy_from_slice(&payload[offset..offset + chunk_size]);

        fragments.push(frag);
        offset += chunk_size;
    }

    fragments
}

pub fn generate_decoy_packets(
    real_packet: &[u8],
    decoys: &[String],
    target_port: u16,
) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut rng = rand::thread_rng();

    for decoy in decoys {
        if let Ok(ip) = decoy.parse::<std::net::Ipv4Addr>() {
            let mut decoy_packet = real_packet.to_vec();
            let decoy_octets = ip.octets();
            decoy_packet[12] = decoy_octets[0];
            decoy_packet[13] = decoy_octets[1];
            decoy_packet[14] = decoy_octets[2];
            decoy_packet[15] = decoy_octets[3];

            let src_port: u16 = rng.gen_range(49152..65535);
            let src_port_be = src_port.to_be_bytes();
            decoy_packet[20] = src_port_be[0];
            decoy_packet[21] = src_port_be[1];

            let dst_port_be = target_port.to_be_bytes();
            decoy_packet[22] = dst_port_be[0];
            decoy_packet[23] = dst_port_be[1];

            decoy_packet[10] = 0;
            decoy_packet[11] = 0;
            let checksum = compute_checksum(&decoy_packet[0..20]);
            decoy_packet[10] = (checksum >> 8) as u8;
            decoy_packet[11] = (checksum & 0xFF) as u8;

            let src_ip = [decoy_octets[0], decoy_octets[1], decoy_octets[2], decoy_octets[3]];
            let dst_ip = [decoy_packet[16], decoy_packet[17], decoy_packet[18], decoy_packet[19]];
            let tcp_checksum = compute_tcp_checksum(src_ip, dst_ip, &decoy_packet[20..]);
            decoy_packet[36] = (tcp_checksum >> 8) as u8;
            decoy_packet[37] = (tcp_checksum & 0xFF) as u8;

            packets.push(decoy_packet);
        }
    }

    packets
}

pub fn shuffle_packets<T>(packets: &mut Vec<T>) {
    let mut rng = rand::thread_rng();
    packets.shuffle(&mut rng);
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct TcpResponse {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub is_syn_ack: bool,
    pub is_rst: bool,
    pub is_fin_ack: bool,
}

pub fn parse_tcp_response(data: &[u8]) -> Option<TcpResponse> {
    if data.len() < IPV4_HEADER_LEN + TCP_HEADER_LEN {
        return None;
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0F) as usize * 4;

    if version != 4 {
        return None;
    }

    if data.len() < ihl + TCP_HEADER_LEN {
        return None;
    }

    let protocol = data[9];
    if protocol != 6 {
        return None;
    }

    let src_ip = [data[12], data[13], data[14], data[15]];

    let tcp_data = &data[ihl..];
    let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
    let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
    let flags = tcp_data[13];

    let is_syn_ack = (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK);
    let is_rst = (flags & TCP_FLAG_RST) != 0;
    let is_fin_ack = (flags & (TCP_FLAG_FIN | TCP_FLAG_ACK)) == (TCP_FLAG_FIN | TCP_FLAG_ACK);

    Some(TcpResponse {
        src_ip,
        src_port,
        dst_port,
        flags,
        is_syn_ack,
        is_rst,
        is_fin_ack,
    })
}

pub fn random_src_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(49152..65535)
}

fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let len = data.len();
    let mut i = 0;
    while i + 1 < len {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < len {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn compute_tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_data: &[u8]) -> u16 {
    let tcp_len = tcp_data.len();
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.push((tcp_len >> 8) as u8);
    pseudo.push((tcp_len & 0xFF) as u8);
    pseudo.extend_from_slice(tcp_data);
    compute_checksum(&pseudo)
}

#[allow(dead_code)]
fn compute_udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_data: &[u8]) -> u16 {
    let udp_len = udp_data.len();
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(17);
    pseudo.push((udp_len >> 8) as u8);
    pseudo.push((udp_len & 0xFF) as u8);
    pseudo.extend_from_slice(udp_data);
    let cksum = compute_checksum(&pseudo);
    if cksum == 0 { 0xFFFF } else { cksum }
}

#[allow(dead_code)]
pub fn build_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;
    let mut buf = vec![0u8; total_len];
    let mut rng = rand::thread_rng();

    buf[0] = 0x45;
    buf[1] = 0x00;
    let total_len_be = (total_len as u16).to_be_bytes();
    buf[2] = total_len_be[0];
    buf[3] = total_len_be[1];
    let id: u16 = rng.gen();
    buf[4] = (id >> 8) as u8;
    buf[5] = (id & 0xFF) as u8;
    buf[6] = 0x40;
    buf[7] = 0x00;
    buf[8] = 64;
    buf[9] = 17;
    buf[10] = 0;
    buf[11] = 0;
    buf[12] = src_ip[0];
    buf[13] = src_ip[1];
    buf[14] = src_ip[2];
    buf[15] = src_ip[3];
    buf[16] = dst_ip[0];
    buf[17] = dst_ip[1];
    buf[18] = dst_ip[2];
    buf[19] = dst_ip[3];

    let ip_checksum = compute_checksum(&buf[0..20]);
    buf[10] = (ip_checksum >> 8) as u8;
    buf[11] = (ip_checksum & 0xFF) as u8;

    let udp_offset = 20;
    let src_port_be = src_port.to_be_bytes();
    buf[udp_offset] = src_port_be[0];
    buf[udp_offset + 1] = src_port_be[1];
    let dst_port_be = dst_port.to_be_bytes();
    buf[udp_offset + 2] = dst_port_be[0];
    buf[udp_offset + 3] = dst_port_be[1];

    let udp_len_be = (udp_len as u16).to_be_bytes();
    buf[udp_offset + 4] = udp_len_be[0];
    buf[udp_offset + 5] = udp_len_be[1];
    buf[udp_offset + 6] = 0;
    buf[udp_offset + 7] = 0;

    buf[udp_offset + 8..udp_offset + 8 + payload.len()].copy_from_slice(payload);

    let udp_checksum = compute_udp_checksum(src_ip, dst_ip, &buf[udp_offset..]);
    if udp_checksum != 0 {
        buf[udp_offset + 6] = (udp_checksum >> 8) as u8;
        buf[udp_offset + 7] = (udp_checksum & 0xFF) as u8;
    }

    buf
}

pub fn parse_ip_header(data: &[u8]) -> Option<IpHeader> {
    if data.len() < IPV4_HEADER_LEN {
        return None;
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    if version != 4 {
        return None;
    }

    let ihl = (version_ihl & 0x0F) as usize * 4;
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let id = u16::from_be_bytes([data[4], data[5]]);
    let flags_and_frag = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_and_frag >> 13) & 0x07;
    let flags = flags as u8;
    let frag_offset = (flags_and_frag & 0x1FFF) * 8;
    let ttl = data[8];
    let protocol = data[9];
    let src_ip = [data[12], data[13], data[14], data[15]];
    let dst_ip = [data[16], data[17], data[18], data[19]];

    Some(IpHeader {
        version,
        ihl,
        total_length,
        id,
        flags,
        frag_offset,
        ttl,
        protocol,
        src_ip,
        dst_ip,
    })
}

#[derive(Debug, Clone)]
pub struct IpHeader {
    #[allow(dead_code)]
    pub version: u8,
    #[allow(dead_code)]
    pub ihl: usize,
    #[allow(dead_code)]
    pub total_length: u16,
    pub id: u16,
    #[allow(dead_code)]
    pub flags: u8,
    #[allow(dead_code)]
    pub frag_offset: u16,
    #[allow(dead_code)]
    pub ttl: u8,
    #[allow(dead_code)]
    pub protocol: u8,
    pub src_ip: [u8; 4],
    #[allow(dead_code)]
    pub dst_ip: [u8; 4],
}
