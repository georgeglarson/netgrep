pub(crate) mod pcap_writer;

use anyhow::{Context, Result};
use pcap::{Capture, Device};
use std::path::Path;

pub struct PacketData<'a> {
    pub data: &'a [u8],
    pub timestamp: std::time::SystemTime,
    pub len: u32,
    pub caplen: u32,
}

pub enum PacketSource {
    Live(Capture<pcap::Active>),
    File(Capture<pcap::Offline>),
}

impl PacketSource {
    pub fn live(interface: &str, snaplen: i32, promisc: bool, bpf: Option<&str>) -> Result<Self> {
        let device = if interface == "any" {
            Device::lookup()?.context("No capture device found")?
        } else {
            Device::list()?
                .into_iter()
                .find(|d| d.name == interface)
                .context(format!("Interface '{}' not found", interface))?
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

        Ok(PacketSource::Live(cap))
    }

    pub fn from_file(path: &Path, bpf: Option<&str>) -> Result<Self> {
        let mut cap = Capture::from_file(path)
            .context(format!("Failed to open pcap file: {}", path.display()))?;

        if let Some(filter) = bpf {
            cap.filter(filter, true)
                .context(format!("Invalid BPF filter: {}", filter))?;
        }

        Ok(PacketSource::File(cap))
    }

    /// Iterate over packets, calling `f` for each one.
    /// Return `false` from `f` to stop capture.
    pub fn for_each_packet<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(PacketData) -> bool,
    {
        loop {
            let raw = match self {
                PacketSource::Live(cap) => cap.next_packet(),
                PacketSource::File(cap) => cap.next_packet(),
            };

            match raw {
                Ok(packet) => {
                    let ts = {
                        let tv = packet.header.ts;
                        std::time::UNIX_EPOCH
                            + std::time::Duration::new(tv.tv_sec as u64, tv.tv_usec as u32 * 1000)
                    };

                    let pkt = PacketData {
                        data: packet.data,
                        timestamp: ts,
                        len: packet.header.len,
                        caplen: packet.header.caplen,
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
