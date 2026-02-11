use anyhow::Result;
use std::io::Write;
use std::time::SystemTime;

/// Minimal pcap file writer (libpcap format).
pub(crate) struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    pub(crate) fn new(mut writer: W) -> Result<Self> {
        let header = PcapGlobalHeader {
            magic: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: 1, // LINKTYPE_ETHERNET
        };
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &header as *const PcapGlobalHeader as *const u8,
                std::mem::size_of::<PcapGlobalHeader>(),
            )
        };
        writer.write_all(bytes)?;
        Ok(PcapWriter { writer })
    }

    pub(crate) fn write_packet(&mut self, data: &[u8], timestamp: SystemTime) -> Result<()> {
        let duration = timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        let pkt_header = PcapPacketHeader {
            ts_sec: duration.as_secs() as u32,
            ts_usec: duration.subsec_micros(),
            incl_len: data.len() as u32,
            orig_len: data.len() as u32,
        };
        let header_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &pkt_header as *const PcapPacketHeader as *const u8,
                std::mem::size_of::<PcapPacketHeader>(),
            )
        };
        self.writer.write_all(header_bytes)?;
        self.writer.write_all(data)?;
        Ok(())
    }
}

#[repr(C)]
struct PcapGlobalHeader {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

#[repr(C)]
struct PcapPacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}
