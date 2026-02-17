#![no_main]
use libfuzzer_sys::fuzz_target;
use netgrep::protocol::http2::{H2Direction, H2Tracker};
use netgrep::protocol::StreamKey;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let mut tracker = H2Tracker::new();
    let key = StreamKey::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        1234,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        443,
    );
    let _ = tracker.process(&key, data, H2Direction::ClientToServer);
});
