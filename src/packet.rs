use pnet::datalink::MacAddr;
use pnet::ip::IpAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use rand::Rng;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

pub fn build_tcp_syn_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: std::net::Ipv4Addr,
    dst_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let total_len = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..ETHERNET_HEADER_LEN]).unwrap();
        eth.set_source(src_mac);
        eth.set_destination(dst_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    {
        let mut ipv4 = MutableIpv4Packet::new(
            &mut buf[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN],
        )
        .unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);
        ipv4.set_ttl(64);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4.set_source(src_ip);
        ipv4.set_destination(dst_ip);
        ipv4.set_flags(Ipv4Flags::DontFragment);
        let mut rng = rand::thread_rng();
        ipv4.set_identification(rng.gen());
    }

    {
        let mut tcp = MutableTcpPacket::new(
            &mut buf[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..],
        )
        .unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        let mut rng = rand::thread_rng();
        tcp.set_sequence(rng.gen::<u32>());
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_urgent_ptr(0);

        let src = std::net::Ipv4Addr::from(src_ip);
        let dst = std::net::Ipv4Addr::from(dst_ip);
        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp.to_immutable(),
            &src,
            &dst,
        );
        tcp.set_checksum(checksum);
    }

    buf
}

pub fn build_udp_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: std::net::Ipv4Addr,
    dst_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..ETHERNET_HEADER_LEN]).unwrap();
        eth.set_source(src_mac);
        eth.set_destination(dst_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    {
        let mut ipv4 = MutableIpv4Packet::new(
            &mut buf[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN],
        )
        .unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length((IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16);
        ipv4.set_ttl(64);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4.set_source(src_ip);
        ipv4.set_destination(dst_ip);
        ipv4.set_flags(Ipv4Flags::DontFragment);
        let mut rng = rand::thread_rng();
        ipv4.set_identification(rng.gen());
    }

    {
        let udp_start = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
        let mut udp = MutableUdpPacket::new(
            &mut buf[udp_start..udp_start + UDP_HEADER_LEN + payload.len()],
        )
        .unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length((UDP_HEADER_LEN + payload.len()) as u16);
        udp.set_payload(payload);

        let src = std::net::Ipv4Addr::from(src_ip);
        let dst = std::net::Ipv4Addr::from(dst_ip);
        let checksum = pnet::packet::udp::ipv4_checksum(
            &udp.to_immutable(),
            &src,
            &dst,
        );
        udp.set_checksum(checksum);
    }

    buf
}

pub fn parse_tcp_response(data: &[u8]) -> Option<TcpResponse> {
    if data.len() < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN {
        return None;
    }

    let eth = EthernetPacket::new(data)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(&data[ETHERNET_HEADER_LEN..])?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let ip_header_len = (ipv4.get_header_length() as usize) * 4;
    let tcp_data = &data[ETHERNET_HEADER_LEN + ip_header_len..];
    let tcp = TcpPacket::new(tcp_data)?;

    Some(TcpResponse {
        src_ip: ipv4.get_source(),
        dst_ip: ipv4.get_destination(),
        src_port: tcp.get_source(),
        dst_port: tcp.get_destination(),
        flags: tcp.get_flags(),
        is_syn_ack: (tcp.get_flags() & TcpFlags::SYN != 0) && (tcp.get_flags() & TcpFlags::ACK != 0),
        is_rst: tcp.get_flags() & TcpFlags::RST != 0,
    })
}

pub fn parse_udp_response(data: &[u8]) -> Option<UdpResponse> {
    if data.len() < ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN {
        return None;
    }

    let eth = EthernetPacket::new(data)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(&data[ETHERNET_HEADER_LEN..])?;

    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
        return Some(UdpResponse {
            src_ip: ipv4.get_source(),
            dst_ip: ipv4.get_destination(),
            is_icmp_unreachable: true,
            payload: Vec::new(),
        });
    }

    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let ip_header_len = (ipv4.get_header_length() as usize) * 4;
    let udp_data = &data[ETHERNET_HEADER_LEN + ip_header_len..];
    let udp = UdpPacket::new(udp_data)?;

    Some(UdpResponse {
        src_ip: ipv4.get_source(),
        dst_ip: ipv4.get_destination(),
        is_icmp_unreachable: false,
        payload: udp.payload().to_vec(),
    })
}

#[derive(Debug)]
pub struct TcpResponse {
    pub src_ip: std::net::Ipv4Addr,
    pub dst_ip: std::net::Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub is_syn_ack: bool,
    pub is_rst: bool,
}

#[derive(Debug)]
pub struct UdpResponse {
    pub src_ip: std::net::Ipv4Addr,
    pub dst_ip: std::net::Ipv4Addr,
    pub is_icmp_unreachable: bool,
    pub payload: Vec<u8>,
}

pub fn random_src_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(49152..65535)
}
