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

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::rdata::{self, RData};
    use simple_dns::{Name, Question, ResourceRecord, CLASS, QCLASS, QTYPE, TYPE};

    /// Helper: build a DNS query packet and serialize to wire bytes.
    fn build_query(id: u16, name: &str, qtype: TYPE) -> Vec<u8> {
        let mut pkt = Packet::new_query(id);
        pkt.questions.push(Question::new(
            Name::new(name).unwrap(),
            QTYPE::TYPE(qtype),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        pkt.build_bytes_vec().unwrap()
    }

    /// Helper: build a DNS response with answer records.
    fn build_response(id: u16, name: &str, qtype: TYPE, answers: Vec<RData>) -> Vec<u8> {
        let mut pkt = Packet::new_reply(id);
        pkt.questions.push(Question::new(
            Name::new(name).unwrap(),
            QTYPE::TYPE(qtype),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        for rdata in answers {
            pkt.answers.push(ResourceRecord::new(
                Name::new(name).unwrap(),
                CLASS::IN,
                3600,
                rdata,
            ));
        }
        pkt.build_bytes_vec().unwrap()
    }

    #[test]
    fn parse_a_query() {
        let wire = build_query(0x1234, "example.com", TYPE::A);
        let info = parse_dns(&wire).unwrap();

        assert!(!info.is_response);
        assert_eq!(info.id, 0x1234);
        assert_eq!(info.opcode, 0);
        assert_eq!(info.rcode, 0);
        assert_eq!(info.questions.len(), 1);
        assert_eq!(info.questions[0].name, "example.com");
        assert_eq!(info.questions[0].qtype, "A");
        assert!(info.answers.is_empty());
    }

    #[test]
    fn parse_a_response() {
        let wire = build_response(
            0xABCD,
            "example.com",
            TYPE::A,
            vec![RData::A(rdata::A {
                address: u32::from(Ipv4Addr::new(93, 184, 216, 34)),
            })],
        );
        let info = parse_dns(&wire).unwrap();

        assert!(info.is_response);
        assert_eq!(info.id, 0xABCD);
        assert_eq!(info.answers.len(), 1);
        assert_eq!(info.answers[0].rtype, "A");
        assert_eq!(info.answers[0].rdata, "93.184.216.34");
        assert_eq!(info.answers[0].ttl, 3600);
    }

    #[test]
    fn parse_aaaa_response() {
        let addr: u128 = Ipv6Addr::new(0x2606, 0x2800, 0x0220, 0x0001, 0, 0, 0, 0).into();
        let wire = build_response(
            1,
            "example.com",
            TYPE::AAAA,
            vec![RData::AAAA(rdata::AAAA { address: addr })],
        );
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.answers[0].rtype, "AAAA");
        assert_eq!(info.answers[0].rdata, "2606:2800:220:1::");
    }

    #[test]
    fn parse_mx_response() {
        let wire = build_response(
            2,
            "example.com",
            TYPE::MX,
            vec![RData::MX(rdata::MX {
                preference: 10,
                exchange: Name::new("mail.example.com").unwrap(),
            })],
        );
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.answers[0].rtype, "MX");
        assert_eq!(info.answers[0].rdata, "10 mail.example.com");
    }

    #[test]
    fn parse_ns_response() {
        let wire = build_response(
            3,
            "example.com",
            TYPE::NS,
            vec![RData::NS(rdata::NS(Name::new("ns1.example.com").unwrap()))],
        );
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.answers[0].rtype, "NS");
        assert_eq!(info.answers[0].rdata, "ns1.example.com");
    }

    #[test]
    fn parse_cname_response() {
        let wire = build_response(
            4,
            "www.example.com",
            TYPE::CNAME,
            vec![RData::CNAME(rdata::CNAME(
                Name::new("example.com").unwrap(),
            ))],
        );
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.answers[0].rtype, "CNAME");
        assert_eq!(info.answers[0].rdata, "example.com");
    }

    #[test]
    fn parse_ptr_response() {
        let wire = build_response(
            5,
            "34.216.184.93.in-addr.arpa",
            TYPE::PTR,
            vec![RData::PTR(rdata::PTR(
                Name::new("example.com").unwrap(),
            ))],
        );
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.answers[0].rtype, "PTR");
        assert_eq!(info.answers[0].rdata, "example.com");
    }

    #[test]
    fn parse_srv_response() {
        let wire = build_response(
            6,
            "_sip._tcp.example.com",
            TYPE::SRV,
            vec![RData::SRV(rdata::SRV {
                priority: 10,
                weight: 60,
                port: 5060,
                target: Name::new("sipserver.example.com").unwrap(),
            })],
        );
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.answers[0].rtype, "SRV");
        assert_eq!(info.answers[0].rdata, "sipserver.example.com:5060 p=10 w=60");
    }

    #[test]
    fn parse_txt_response() {
        let txt = rdata::TXT::new().with_string("v=spf1 include:example.com ~all").unwrap();
        let wire = build_response(7, "example.com", TYPE::TXT, vec![RData::TXT(txt)]);
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.answers[0].rtype, "TXT");
        // TXT attributes() parses key=value pairs
        assert!(info.answers[0].rdata.contains("v=spf1 include:example.com ~all"));
    }

    #[test]
    fn parse_multiple_answers() {
        let wire = build_response(
            8,
            "example.com",
            TYPE::A,
            vec![
                RData::A(rdata::A { address: u32::from(Ipv4Addr::new(1, 2, 3, 4)) }),
                RData::A(rdata::A { address: u32::from(Ipv4Addr::new(5, 6, 7, 8)) }),
                RData::A(rdata::A { address: u32::from(Ipv4Addr::new(9, 10, 11, 12)) }),
            ],
        );
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.answers.len(), 3);
        assert_eq!(info.answers[0].rdata, "1.2.3.4");
        assert_eq!(info.answers[1].rdata, "5.6.7.8");
        assert_eq!(info.answers[2].rdata, "9.10.11.12");
    }

    #[test]
    fn parse_nxdomain_response() {
        let mut pkt = Packet::new_reply(9);
        *pkt.rcode_mut() = RCODE::NameError;
        pkt.questions.push(Question::new(
            Name::new("doesnotexist.example.com").unwrap(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let wire = pkt.build_bytes_vec().unwrap();
        let info = parse_dns(&wire).unwrap();

        assert!(info.is_response);
        assert_eq!(info.rcode, 3);
        assert!(info.answers.is_empty());
        assert!(info.display_string().contains("NXDOMAIN"));
    }

    #[test]
    fn parse_servfail_response() {
        let mut pkt = Packet::new_reply(10);
        *pkt.rcode_mut() = RCODE::ServerFailure;
        pkt.questions.push(Question::new(
            Name::new("example.com").unwrap(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let wire = pkt.build_bytes_vec().unwrap();
        let info = parse_dns(&wire).unwrap();

        assert_eq!(info.rcode, 2);
        assert!(info.display_string().contains("SERVFAIL"));
    }

    #[test]
    fn display_string_query() {
        let wire = build_query(11, "google.com", TYPE::A);
        let info = parse_dns(&wire).unwrap();
        let display = info.display_string();

        assert!(display.contains("google.com"));
        assert!(display.contains("A"));
        assert!(display.contains("NOERROR"));
    }

    #[test]
    fn display_string_response_contains_rdata() {
        let wire = build_response(
            12,
            "example.com",
            TYPE::A,
            vec![RData::A(rdata::A {
                address: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            })],
        );
        let info = parse_dns(&wire).unwrap();
        let display = info.display_string();

        assert!(display.contains("example.com"));
        assert!(display.contains("10.0.0.1"));
        assert!(display.contains("NOERROR"));
    }

    #[test]
    fn display_string_mx_response() {
        let wire = build_response(
            13,
            "github.com",
            TYPE::MX,
            vec![RData::MX(rdata::MX {
                preference: 1,
                exchange: Name::new("aspmx.l.google.com").unwrap(),
            })],
        );
        let info = parse_dns(&wire).unwrap();
        let display = info.display_string();

        // Pattern matching against display_string should find "google" in MX rdata
        assert!(display.contains("google"));
        assert!(display.contains("github.com"));
    }

    #[test]
    fn parse_authority_records() {
        let mut pkt = Packet::new_reply(14);
        pkt.questions.push(Question::new(
            Name::new("example.com").unwrap(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        pkt.name_servers.push(ResourceRecord::new(
            Name::new("example.com").unwrap(),
            CLASS::IN,
            86400,
            RData::NS(rdata::NS(Name::new("ns1.example.com").unwrap())),
        ));
        let wire = pkt.build_bytes_vec().unwrap();
        let info = parse_dns(&wire).unwrap();

        assert!(info.answers.is_empty());
        assert_eq!(info.authorities.len(), 1);
        assert_eq!(info.authorities[0].rtype, "NS");
        assert_eq!(info.authorities[0].rdata, "ns1.example.com");
        assert!(info.display_string().contains("ns1.example.com"));
    }

    #[test]
    fn parse_garbage_returns_none() {
        assert!(parse_dns(&[]).is_none());
        assert!(parse_dns(&[0xFF; 4]).is_none());
        assert!(parse_dns(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn parse_different_qtypes() {
        for (qtype, expected) in [
            (TYPE::A, "A"),
            (TYPE::AAAA, "AAAA"),
            (TYPE::MX, "MX"),
            (TYPE::NS, "NS"),
            (TYPE::CNAME, "CNAME"),
            (TYPE::PTR, "PTR"),
            (TYPE::SOA, "SOA"),
            (TYPE::SRV, "SRV"),
            (TYPE::TXT, "TXT"),
        ] {
            let wire = build_query(100, "test.com", qtype);
            let info = parse_dns(&wire).unwrap();
            assert_eq!(info.questions[0].qtype, expected, "qtype mismatch for {:?}", qtype);
        }
    }
}
