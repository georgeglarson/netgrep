#![no_main]
use libfuzzer_sys::fuzz_target;
use netgrep::protocol::LinkType;

fuzz_target!(|data: &[u8]| {
    let _ = netgrep::protocol::parse_packet(data, LinkType::Ethernet);
});
