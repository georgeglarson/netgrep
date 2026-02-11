pub mod http;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::net::IpAddr;

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
    pub ack: Option<u32>,
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
pub fn parse_packet(data: &[u8]) -> Option<ParsedPacket> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;

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

    let (src_port, dst_port, transport, tcp_flags, seq, ack, payload) = match &sliced.transport {
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
            Some(tcp.acknowledgment_number()),
            tcp.payload().to_vec(),
        ),
        Some(TransportSlice::Udp(udp)) => (
            Some(udp.source_port()),
            Some(udp.destination_port()),
            Transport::Udp,
            None,
            None,
            None,
            udp.payload().to_vec(),
        ),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
            (None, None, Transport::Icmp, None, None, None, Vec::new())
        }
        _ => (None, None, Transport::Other, None, None, None, Vec::new()),
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
        ack,
    })
}
