pub(crate) mod pcap_writer;

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
    ) -> Result<Self> {
        let device = match interface {
            Some(name) => Device::list()?
                .into_iter()
                .find(|d| d.name == name)
                .context(format!("Interface '{}' not found", name))?,
            None => Device::lookup()?.context("No capture device found")?,
        };

        let mut cap = Capture::from_device(device)?
            .snaplen(snaplen)
            .promisc(promisc)
            .timeout(1000)
            .open()
            .context("Failed to open capture device")?;

        if let Some(filter) = bpf {
            cap.filter(filter, true)
                .context(format!("Invalid BPF filter: {}", filter))?;
        }

        let lt = link_type_from_pcap(cap.get_datalink());
        Ok(PacketSource::Live(cap, lt))
    }

    pub fn from_file(path: &Path, bpf: Option<&str>) -> Result<Self> {
        let mut cap = Capture::from_file(path)
            .context(format!("Failed to open pcap file: {}", path.display()))?;

        if let Some(filter) = bpf {
            cap.filter(filter, true)
                .context(format!("Invalid BPF filter: {}", filter))?;
        }

        let lt = link_type_from_pcap(cap.get_datalink());
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
                        let secs = (tv.tv_sec as i64).max(0) as u64;
                        // tv_usec is microseconds (max 999_999) from libpcap's timeval.
                        // Clamp to valid range to guard against malformed pcap/pcapng files.
                        let usec = (tv.tv_usec as i64).max(0).min(999_999) as u32;
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

fn link_type_from_pcap(dl: pcap::Linktype) -> LinkType {
    match dl.0 {
        1 => LinkType::Ethernet,     // DLT_EN10MB
        12 | 101 => LinkType::RawIp, // DLT_RAW
        113 => LinkType::LinuxSll,   // DLT_LINUX_SLL
        _ => {
            eprintln!(
                "Warning: unsupported link type {} ({}), assuming Ethernet",
                dl.get_name().unwrap_or_default(),
                dl.0
            );
            LinkType::Ethernet
        }
    }
}
