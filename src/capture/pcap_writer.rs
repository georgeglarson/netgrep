use anyhow::Result;
use std::io::Write;
use std::time::SystemTime;

/// Minimal pcap file writer (libpcap format).
/// Uses native-endian byte order (indicated by magic number 0xa1b2c3d4).
pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut writer: W, link_type: u32) -> Result<Self> {
        // Global header: magic, version 2.4, timezone 0, sigfigs 0, snaplen 65535
        writer.write_all(&0xa1b2c3d4u32.to_ne_bytes())?; // magic
        writer.write_all(&2u16.to_ne_bytes())?; // version_major
        writer.write_all(&4u16.to_ne_bytes())?; // version_minor
        writer.write_all(&0i32.to_ne_bytes())?; // thiszone
        writer.write_all(&0u32.to_ne_bytes())?; // sigfigs
        writer.write_all(&65535u32.to_ne_bytes())?; // snaplen
        writer.write_all(&link_type.to_ne_bytes())?; // network
        Ok(PcapWriter { writer })
    }

    pub fn write_packet(&mut self, data: &[u8], timestamp: SystemTime) -> Result<()> {
        let duration = timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        // pcap format uses u32 for ts_sec (wraps after 2106-02-07).
        // Truncation is inherent to the format. Pre-epoch timestamps
        // produce Duration::default() (0) via unwrap_or_default() above.
        let ts_sec = duration.as_secs() as u32;
        let ts_usec = duration.subsec_micros();
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);

        // Build packet record in a single buffer to avoid partial writes on error
        let mut record = Vec::with_capacity(16 + data.len());
        record.extend_from_slice(&ts_sec.to_ne_bytes());
        record.extend_from_slice(&ts_usec.to_ne_bytes());
        record.extend_from_slice(&len.to_ne_bytes()); // incl_len
        record.extend_from_slice(&len.to_ne_bytes()); // orig_len
        record.extend_from_slice(data);
        self.writer.write_all(&record)?;
        Ok(())
    }
}

impl<W: Write> Drop for PcapWriter<W> {
    fn drop(&mut self) {
        if let Err(e) = self.writer.flush() {
            eprintln!("Warning: failed to flush pcap output on close: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    fn read_u32_ne(data: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap())
    }

    fn read_u16_ne(data: &[u8], offset: usize) -> u16 {
        u16::from_ne_bytes(data[offset..offset + 2].try_into().unwrap())
    }

    #[test]
    fn global_header_correct() {
        let buf = Vec::new();
        let writer = PcapWriter::new(buf, 1).unwrap();
        let data = &writer.writer;
        assert_eq!(data.len(), 24); // Global header is 24 bytes
        assert_eq!(read_u32_ne(data, 0), 0xa1b2c3d4); // magic
        assert_eq!(read_u16_ne(data, 4), 2); // version_major
        assert_eq!(read_u16_ne(data, 6), 4); // version_minor
        assert_eq!(read_u32_ne(data, 16), 65535); // snaplen
        assert_eq!(read_u32_ne(data, 20), 1); // network (Ethernet)
    }

    #[test]
    fn global_header_linux_sll_link_type() {
        let buf = Vec::new();
        let writer = PcapWriter::new(buf, 113).unwrap();
        let data = &writer.writer;
        assert_eq!(read_u32_ne(data, 20), 113); // network (Linux SLL)
    }

    #[test]
    fn write_packet_epoch() {
        let buf = Vec::new();
        let mut writer = PcapWriter::new(buf, 1).unwrap();
        writer.write_packet(b"test", std::time::UNIX_EPOCH).unwrap();
        let data = &writer.writer;
        // Global header (24) + packet header (16) + payload (4) = 44
        assert_eq!(data.len(), 44);
        assert_eq!(read_u32_ne(data, 24), 0); // ts_sec
        assert_eq!(read_u32_ne(data, 28), 0); // ts_usec
        assert_eq!(read_u32_ne(data, 32), 4); // incl_len
        assert_eq!(read_u32_ne(data, 36), 4); // orig_len
        assert_eq!(&data[40..], b"test");
    }

    #[test]
    fn write_packet_with_timestamp() {
        let buf = Vec::new();
        let mut writer = PcapWriter::new(buf, 1).unwrap();
        let ts = std::time::UNIX_EPOCH + Duration::new(1000, 500_000_000); // 1000s + 500ms
        writer.write_packet(b"hi", ts).unwrap();
        let data = &writer.writer;
        assert_eq!(read_u32_ne(data, 24), 1000); // ts_sec
        assert_eq!(read_u32_ne(data, 28), 500_000); // ts_usec (500ms = 500000us)
        assert_eq!(read_u32_ne(data, 32), 2); // incl_len
    }

    #[test]
    fn write_multiple_packets() {
        let buf = Vec::new();
        let mut writer = PcapWriter::new(buf, 1).unwrap();
        writer.write_packet(b"aaa", std::time::UNIX_EPOCH).unwrap();
        writer
            .write_packet(b"bbbbb", std::time::UNIX_EPOCH)
            .unwrap();
        let data = &writer.writer;
        // 24 (global) + 16+3 (pkt1) + 16+5 (pkt2) = 64
        assert_eq!(data.len(), 64);
        // Second packet payload
        assert_eq!(&data[59..], b"bbbbb");
    }

    #[test]
    fn drop_flushes() {
        let buf = Cursor::new(Vec::new());
        let writer = PcapWriter::new(buf, 1).unwrap();
        // Drop should not panic
        drop(writer);
    }

    #[test]
    fn write_empty_packet() {
        let buf = Vec::new();
        let mut writer = PcapWriter::new(buf, 1).unwrap();
        writer.write_packet(&[], std::time::UNIX_EPOCH).unwrap();
        let data = &writer.writer;
        assert_eq!(data.len(), 24 + 16); // no payload bytes
        assert_eq!(read_u32_ne(data, 32), 0); // incl_len = 0
    }
}
