pub mod dns;
pub mod http;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::net::IpAddr;

/// Link-layer type of the capture, determines how to parse raw packet bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    LinuxSll,
    RawIp,
}

impl LinkType {
    /// Return the pcap link-layer header type value (DLT_*).
    pub fn pcap_link_type(self) -> u32 {
        match self {
            LinkType::Ethernet => 1,   // DLT_EN10MB
            LinkType::RawIp => 101,    // DLT_RAW
            LinkType::LinuxSll => 113, // DLT_LINUX_SLL
        }
    }
}

/// A parsed packet with extracted header info and payload.
#[derive(Debug)]
pub struct ParsedPacket {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport: Transport,
    pub payload: Vec<u8>,
    pub tcp_flags: Option<TcpFlags>,
    pub seq: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

impl ParsedPacket {
    pub fn is_tcp(&self) -> bool {
        self.transport == Transport::Tcp
    }

    /// Check if this packet is on a DNS port (53 or 5353/mDNS).
    pub fn is_dns_port(&self) -> bool {
        const DNS_PORTS: [u16; 2] = [53, 5353];
        self.src_port.is_some_and(|p| DNS_PORTS.contains(&p))
            || self.dst_port.is_some_and(|p| DNS_PORTS.contains(&p))
    }

    /// Return payload as a lossy UTF-8 string for matching.
    pub fn payload_str(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }

    /// Connection tuple for stream tracking.
    pub fn stream_key(&self) -> Option<StreamKey> {
        match (self.src_ip, self.dst_ip, self.src_port, self.dst_port) {
            (Some(si), Some(di), Some(sp), Some(dp)) => Some(StreamKey::new(si, sp, di, dp)),
            _ => None,
        }
    }
}

/// Bidirectional stream identifier — normalized so (A->B) == (B->A).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StreamKey {
    pub addr_a: IpAddr,
    pub port_a: u16,
    pub addr_b: IpAddr,
    pub port_b: u16,
}

impl StreamKey {
    pub fn new(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> Self {
        // Normalize IPv6-mapped-IPv4 (::ffff:x.x.x.x) to plain IPv4 so that
        // dual-stack connections map to the same stream.
        let src = normalize_ip(src);
        let dst = normalize_ip(dst);
        if (src, src_port) <= (dst, dst_port) {
            StreamKey {
                addr_a: src,
                port_a: src_port,
                addr_b: dst,
                port_b: dst_port,
            }
        } else {
            StreamKey {
                addr_a: dst,
                port_a: dst_port,
                addr_b: src,
                port_b: src_port,
            }
        }
    }
}

/// Convert IPv6-mapped-IPv4 addresses to their IPv4 equivalent.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        other => other,
    }
}

impl std::fmt::Display for StreamKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} <-> {}:{}",
            self.addr_a, self.port_a, self.addr_b, self.port_b
        )
    }
}

/// Parse raw packet bytes into a ParsedPacket.
pub fn parse_packet(data: &[u8], link_type: LinkType) -> Option<ParsedPacket> {
    let sliced = match link_type {
        LinkType::Ethernet => SlicedPacket::from_ethernet(data).ok()?,
        LinkType::RawIp => SlicedPacket::from_ip(data).ok()?,
        LinkType::LinuxSll => {
            // Linux cooked capture v1: 16-byte header, then IP packet
            if data.len() < 16 {
                return None;
            }
            SlicedPacket::from_ip(&data[16..]).ok()?
        }
    };

    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => (
            Some(IpAddr::V4(ipv4.header().source_addr())),
            Some(IpAddr::V4(ipv4.header().destination_addr())),
        ),
        Some(NetSlice::Ipv6(ipv6)) => (
            Some(IpAddr::V6(ipv6.header().source_addr())),
            Some(IpAddr::V6(ipv6.header().destination_addr())),
        ),
        _ => (None, None),
    };

    let (src_port, dst_port, transport, tcp_flags, seq, payload) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            Some(tcp.source_port()),
            Some(tcp.destination_port()),
            Transport::Tcp,
            Some(TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
                psh: tcp.psh(),
            }),
            Some(tcp.sequence_number()),
            tcp.payload().to_vec(),
        ),
        Some(TransportSlice::Udp(udp)) => (
            Some(udp.source_port()),
            Some(udp.destination_port()),
            Transport::Udp,
            None,
            None,
            udp.payload().to_vec(),
        ),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => (
            None,
            None,
            Transport::Icmp,
            None,
            None,
            sliced
                .ip_payload()
                .map(|p| p.payload.to_vec())
                .unwrap_or_default(),
        ),
        _ => (None, None, Transport::Other, None, None, Vec::new()),
    };

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        transport,
        payload,
        tcp_flags,
        seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -- StreamKey tests --

    #[test]
    fn stream_key_bidirectional() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let k1 = StreamKey::new(a, 1234, b, 80);
        let k2 = StreamKey::new(b, 80, a, 1234);
        assert_eq!(k1, k2);
    }

    #[test]
    fn stream_key_different_ports_not_equal() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let k1 = StreamKey::new(a, 80, b, 1234);
        let k2 = StreamKey::new(a, 1234, b, 80);
        assert_ne!(k1, k2);
    }

    #[test]
    fn stream_key_ipv6_bidirectional() {
        let a = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let b = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        let k1 = StreamKey::new(a, 443, b, 5000);
        let k2 = StreamKey::new(b, 5000, a, 443);
        assert_eq!(k1, k2);
    }

    #[test]
    fn stream_key_same_ip_different_ports() {
        let a = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let k1 = StreamKey::new(a, 1000, a, 2000);
        let k2 = StreamKey::new(a, 2000, a, 1000);
        assert_eq!(k1, k2);
    }

    #[test]
    fn stream_key_display() {
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let k = StreamKey::new(a, 80, b, 443);
        let s = k.to_string();
        assert!(s.contains("1.2.3.4"));
        assert!(s.contains("5.6.7.8"));
        assert!(s.contains("<->"));
    }

    #[test]
    fn stream_key_port_boundary() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let k = StreamKey::new(a, 0, b, 65535);
        // Should not panic, normalization should work at extremes
        assert!(k.port_a == 0 || k.port_b == 0);
        assert!(k.port_a == 65535 || k.port_b == 65535);
    }

    // -- is_dns_port tests --

    fn make_udp_packet(src_port: Option<u16>, dst_port: Option<u16>) -> ParsedPacket {
        ParsedPacket {
            src_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            src_port,
            dst_port,
            transport: Transport::Udp,
            payload: Vec::new(),
            tcp_flags: None,
            seq: None,
        }
    }

    #[test]
    fn is_dns_port_src_53() {
        assert!(make_udp_packet(Some(53), Some(12345)).is_dns_port());
    }

    #[test]
    fn is_dns_port_dst_53() {
        assert!(make_udp_packet(Some(12345), Some(53)).is_dns_port());
    }

    #[test]
    fn is_dns_port_mdns_5353() {
        assert!(make_udp_packet(Some(5353), Some(5353)).is_dns_port());
    }

    #[test]
    fn is_dns_port_not_dns() {
        assert!(!make_udp_packet(Some(80), Some(443)).is_dns_port());
    }

    #[test]
    fn is_dns_port_none_ports() {
        assert!(!make_udp_packet(None, None).is_dns_port());
    }

    #[test]
    fn is_dns_port_adjacent_ports_not_dns() {
        assert!(!make_udp_packet(Some(52), Some(54)).is_dns_port());
        assert!(!make_udp_packet(Some(5352), Some(5354)).is_dns_port());
    }

    // -- parse_packet tests --

    /// Build a minimal Ethernet + IPv4 + TCP packet.
    fn build_eth_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags_byte: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::PacketBuilder;
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src_ip, dst_ip, 64)
            .tcp(src_port, dst_port, seq, 65535);
        let mut buf = Vec::new();
        builder.write(&mut buf, payload).unwrap();
        // Set TCP flags manually (offset 47 in the packet for standard headers)
        // Find TCP flags byte: eth(14) + ipv4(20) + tcp offset(13) = 47
        buf[14 + 20 + 13] = flags_byte;
        buf
    }

    /// Build a minimal Ethernet + IPv4 + UDP packet.
    fn build_eth_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::PacketBuilder;
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src_ip, dst_ip, 64)
            .udp(src_port, dst_port);
        let mut buf = Vec::new();
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    #[test]
    fn parse_ethernet_tcp_packet() {
        let data = build_eth_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            100,
            0x18, // PSH+ACK
            b"hello",
        );
        let pkt = parse_packet(&data, LinkType::Ethernet).unwrap();
        assert_eq!(pkt.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(pkt.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(pkt.src_port, Some(1234));
        assert_eq!(pkt.dst_port, Some(80));
        assert_eq!(pkt.transport, Transport::Tcp);
        assert_eq!(pkt.payload, b"hello");
        assert!(pkt.tcp_flags.is_some());
        assert_eq!(pkt.seq, Some(100));
    }

    #[test]
    fn parse_ethernet_udp_packet() {
        let data = build_eth_udp_packet([192, 168, 1, 1], [8, 8, 8, 8], 5000, 53, b"dns query");
        let pkt = parse_packet(&data, LinkType::Ethernet).unwrap();
        assert_eq!(pkt.transport, Transport::Udp);
        assert_eq!(pkt.src_port, Some(5000));
        assert_eq!(pkt.dst_port, Some(53));
        assert_eq!(pkt.payload, b"dns query");
        assert!(pkt.tcp_flags.is_none());
        assert!(pkt.seq.is_none());
    }

    #[test]
    fn parse_raw_ip_tcp_packet() {
        // Build an Ethernet packet and strip the 14-byte Ethernet header
        let eth = build_eth_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 80, 443, 1, 0x02, b"SYN");
        let raw_ip = &eth[14..]; // strip Ethernet header
        let pkt = parse_packet(raw_ip, LinkType::RawIp).unwrap();
        assert_eq!(pkt.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(pkt.transport, Transport::Tcp);
    }

    #[test]
    fn parse_linux_sll_packet() {
        // Build an Ethernet packet and replace Ethernet header with 16-byte SLL header
        let eth = build_eth_udp_packet([172, 16, 0, 1], [172, 16, 0, 2], 1234, 80, b"test");
        let ip_data = &eth[14..]; // strip Ethernet header

        // Build a fake Linux SLL v1 header (16 bytes)
        let mut sll = vec![0u8; 16];
        sll[14] = 0x08; // Protocol type: IPv4 (0x0800)
        sll[15] = 0x00;
        sll.extend_from_slice(ip_data);

        let pkt = parse_packet(&sll, LinkType::LinuxSll).unwrap();
        assert_eq!(pkt.src_ip, Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert_eq!(pkt.transport, Transport::Udp);
    }

    #[test]
    fn parse_linux_sll_too_short() {
        let data = vec![0u8; 10]; // Less than 16 bytes
        assert!(parse_packet(&data, LinkType::LinuxSll).is_none());
    }

    #[test]
    fn parse_truncated_data() {
        assert!(parse_packet(&[0, 1, 2], LinkType::Ethernet).is_none());
    }

    #[test]
    fn parse_empty_payload_tcp() {
        // TCP SYN with no payload
        let data = build_eth_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0, 0x02, &[]);
        let pkt = parse_packet(&data, LinkType::Ethernet).unwrap();
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn parse_tcp_syn_flag() {
        let data = build_eth_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0, 0x02, &[]); // SYN
        let pkt = parse_packet(&data, LinkType::Ethernet).unwrap();
        let flags = pkt.tcp_flags.unwrap();
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);
        assert!(!flags.rst);
        assert!(!flags.psh);
    }

    #[test]
    fn parse_tcp_fin_ack_flags() {
        let data = build_eth_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            0,
            0x11, // FIN+ACK
            &[],
        );
        let pkt = parse_packet(&data, LinkType::Ethernet).unwrap();
        let flags = pkt.tcp_flags.unwrap();
        assert!(flags.fin);
        assert!(flags.ack);
        assert!(!flags.syn);
    }
}
