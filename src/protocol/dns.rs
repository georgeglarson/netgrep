use serde::Serialize;
use simple_dns::{rdata::RData, Packet, PacketFlag, OPCODE, QTYPE, RCODE};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Serialize)]
pub struct DnsInfo {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

#[derive(Debug, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: String,
}

#[derive(Debug, Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub rdata: String,
}

pub fn parse_dns(data: &[u8]) -> Option<DnsInfo> {
    let packet = Packet::parse(data).ok()?;

    let is_response = packet.has_flags(PacketFlag::RESPONSE);
    let opcode = opcode_to_u8(packet.opcode());
    let rcode = rcode_to_u8(packet.rcode());

    let questions = packet
        .questions
        .iter()
        .map(|q| DnsQuestion {
            name: q.qname.to_string(),
            qtype: qtype_str(&q.qtype),
        })
        .collect();

    let answers = packet.answers.iter().map(convert_record).collect();
    let authorities = packet.name_servers.iter().map(convert_record).collect();
    let additionals = packet
        .additional_records
        .iter()
        .map(convert_record)
        .collect();

    Some(DnsInfo {
        id: packet.id(),
        is_response,
        opcode,
        rcode,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn convert_record(rr: &simple_dns::ResourceRecord) -> DnsRecord {
    DnsRecord {
        name: rr.name.to_string(),
        rtype: rdata_type_str(&rr.rdata),
        ttl: rr.ttl,
        rdata: rdata_to_string(&rr.rdata),
    }
}

fn rdata_type_str(rdata: &RData) -> String {
    match rdata {
        RData::A(_) => "A".into(),
        RData::AAAA(_) => "AAAA".into(),
        RData::CNAME(_) => "CNAME".into(),
        RData::MX(_) => "MX".into(),
        RData::NS(_) => "NS".into(),
        RData::PTR(_) => "PTR".into(),
        RData::SOA(_) => "SOA".into(),
        RData::SRV(_) => "SRV".into(),
        RData::TXT(_) => "TXT".into(),
        RData::CAA(_) => "CAA".into(),
        RData::DNSKEY(_) => "DNSKEY".into(),
        RData::DS(_) => "DS".into(),
        RData::RRSIG(_) => "RRSIG".into(),
        RData::NSEC(_) => "NSEC".into(),
        RData::HTTPS(_) => "HTTPS".into(),
        RData::SVCB(_) => "SVCB".into(),
        RData::OPT(_) => "OPT".into(),
        _ => format!("{:?}", rdata),
    }
}

fn rdata_to_string(rdata: &RData) -> String {
    match rdata {
        RData::A(a) => Ipv4Addr::from(a.address).to_string(),
        RData::AAAA(aaaa) => Ipv6Addr::from(aaaa.address).to_string(),
        RData::CNAME(cname) => cname.0.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
        RData::NS(ns) => ns.0.to_string(),
        RData::PTR(ptr) => ptr.0.to_string(),
        RData::SOA(soa) => format!("{} {} {}", soa.mname, soa.rname, soa.serial),
        RData::SRV(srv) => format!("{}:{} p={} w={}", srv.target, srv.port, srv.priority, srv.weight),
        RData::TXT(txt) => txt.attributes().into_iter().map(|(k, v)| {
            if let Some(val) = v {
                format!("{}={}", k, val)
            } else {
                k
            }
        }).collect::<Vec<_>>().join(" "),
        RData::CAA(caa) => format!("{:?}", caa),
        RData::OPT(_) => String::new(),
        _ => format!("{:?}", rdata),
    }
}

fn qtype_str(qtype: &QTYPE) -> String {
    match qtype {
        QTYPE::TYPE(t) => format!("{:?}", t),
        QTYPE::ANY => "ANY".into(),
        QTYPE::AXFR => "AXFR".into(),
        QTYPE::IXFR => "IXFR".into(),
        QTYPE::MAILB => "MAILB".into(),
        QTYPE::MAILA => "MAILA".into(),
    }
}

fn opcode_to_u8(opcode: OPCODE) -> u8 {
    match opcode {
        OPCODE::StandardQuery => 0,
        OPCODE::InverseQuery => 1,
        OPCODE::ServerStatusRequest => 2,
        OPCODE::Notify => 4,
        OPCODE::Update => 5,
        _ => 255,
    }
}

fn rcode_to_u8(rcode: RCODE) -> u8 {
    match rcode {
        RCODE::NoError => 0,
        RCODE::FormatError => 1,
        RCODE::ServerFailure => 2,
        RCODE::NameError => 3,
        RCODE::NotImplemented => 4,
        RCODE::Refused => 5,
        _ => 255,
    }
}

pub fn rcode_str(code: u8) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

impl DnsInfo {
    /// Format for regex matching — includes domain names, record data, etc.
    pub fn display_string(&self) -> String {
        let mut out = String::new();

        for q in &self.questions {
            out.push_str(&q.name);
            out.push(' ');
            out.push_str(&q.qtype);
            out.push(' ');
        }

        for r in self.answers.iter().chain(&self.authorities).chain(&self.additionals) {
            out.push_str(&r.name);
            out.push(' ');
            out.push_str(&r.rtype);
            out.push(' ');
            out.push_str(&r.rdata);
            out.push(' ');
        }

        out.push_str(rcode_str(self.rcode));
        out
    }
}
