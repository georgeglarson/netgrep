pub mod pcap_writer;

use anyhow::{Context, Result};
use pcap::{Capture, Device};
use std::path::Path;

use crate::protocol::LinkType;

pub struct PacketData<'a> {
    pub data: &'a [u8],
    pub timestamp: std::time::SystemTime,
}

pub enum PacketSource {
    Live(Capture<pcap::Active>, LinkType),
    File(Capture<pcap::Offline>, LinkType),
}

impl PacketSource {
    pub fn link_type(&self) -> LinkType {
        match self {
            PacketSource::Live(_, lt) | PacketSource::File(_, lt) => *lt,
        }
    }

    pub fn live(
        interface: Option<&str>,
        snaplen: i32,
        promisc: bool,
        bpf: Option<&str>,
        buffer_size: Option<i32>,
    ) -> Result<Self> {
        let device = match interface {
            Some(name) => Device::list()?
                .into_iter()
                .find(|d| d.name == name)
                .context(format!("Interface '{}' not found", name))?,
            None => Device::lookup()?.context("No capture device found")?,
        };

        let mut builder = Capture::from_device(device)?
            .snaplen(snaplen)
            .promisc(promisc)
            .timeout(1000);

        if let Some(kb) = buffer_size {
            // L1: Use checked_mul to avoid i32 overflow on large values.
            let bytes = kb.checked_mul(1024).context("buffer_size overflow")?;
            builder = builder.buffer_size(bytes);
        }

        let mut cap = builder.open().context("Failed to open capture device")?;

        if let Some(filter) = bpf {
            cap.filter(filter, true)
                .context(format!("Invalid BPF filter: {}", filter))?;
        }

        let lt = link_type_from_pcap(cap.get_datalink())?;
        Ok(PacketSource::Live(cap, lt))
    }

    pub fn from_file(path: &Path, bpf: Option<&str>) -> Result<Self> {
        let mut cap = Capture::from_file(path)
            .context(format!("Failed to open pcap file: {}", path.display()))?;

        if let Some(filter) = bpf {
            cap.filter(filter, true)
                .context(format!("Invalid BPF filter: {}", filter))?;
        }

        let lt = link_type_from_pcap(cap.get_datalink())?;
        Ok(PacketSource::File(cap, lt))
    }

    /// Iterate over packets, calling `f` for each one.
    /// Return `false` from `f` to stop capture.
    pub fn for_each_packet<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(PacketData) -> bool,
    {
        loop {
            let raw = match self {
                PacketSource::Live(cap, _) => cap.next_packet(),
                PacketSource::File(cap, _) => cap.next_packet(),
            };

            match raw {
                Ok(packet) => {
                    let ts = {
                        let tv = packet.header.ts;
                        let secs = tv.tv_sec.max(0) as u64;
                        // tv_usec is microseconds (max 999_999) from libpcap's timeval.
                        // Clamp to valid range to guard against malformed pcap/pcapng files.
                        let usec = tv.tv_usec.clamp(0, 999_999) as u32;
                        std::time::UNIX_EPOCH + std::time::Duration::new(secs, usec * 1000)
                    };

                    let pkt = PacketData {
                        data: packet.data,
                        timestamp: ts,
                    };

                    if !f(pkt) {
                        break;
                    }
                }
                Err(pcap::Error::NoMorePackets) => break,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }
}

fn link_type_from_pcap(dl: pcap::Linktype) -> Result<LinkType> {
    match dl.0 {
        1 => Ok(LinkType::Ethernet),     // DLT_EN10MB
        12 | 101 => Ok(LinkType::RawIp), // L28: DLT_RAW (12 = BSD, 101 = LINKTYPE_RAW)
        113 => Ok(LinkType::LinuxSll),   // DLT_LINUX_SLL
        276 => Ok(LinkType::LinuxSll2),  // DLT_LINUX_SLL2
        _ => {
            // L29: Use "unknown" instead of unwrap_or_default() for clearer error message
            anyhow::bail!(
                "Unsupported link type: {} (DLT {}). \
                 Supported: Ethernet (1), Raw IP (12/101), Linux SLL (113), Linux SLL2 (276)",
                dl.get_name().unwrap_or("unknown".to_string()),
                dl.0
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T7: Test link_type_from_pcap with known/unknown DLT values
    #[test]
    fn link_type_from_pcap_ethernet() {
        let lt = link_type_from_pcap(pcap::Linktype(1)).unwrap();
        assert!(matches!(lt, LinkType::Ethernet));
    }

    #[test]
    fn link_type_from_pcap_raw_ip_12() {
        let lt = link_type_from_pcap(pcap::Linktype(12)).unwrap();
        assert!(matches!(lt, LinkType::RawIp));
    }

    #[test]
    fn link_type_from_pcap_raw_ip_101() {
        let lt = link_type_from_pcap(pcap::Linktype(101)).unwrap();
        assert!(matches!(lt, LinkType::RawIp));
    }

    #[test]
    fn link_type_from_pcap_linux_sll() {
        let lt = link_type_from_pcap(pcap::Linktype(113)).unwrap();
        assert!(matches!(lt, LinkType::LinuxSll));
    }

    #[test]
    fn link_type_from_pcap_linux_sll2() {
        let lt = link_type_from_pcap(pcap::Linktype(276)).unwrap();
        assert!(matches!(lt, LinkType::LinuxSll2));
    }

    #[test]
    fn link_type_from_pcap_unknown_dlt() {
        let result = link_type_from_pcap(pcap::Linktype(999));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("DLT 999"));
    }
}
