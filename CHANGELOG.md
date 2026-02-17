# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-17

### Added

- Live capture and pcap/pcapng file reading
- BPF filter support (`-F`)
- Regex matching against payloads with color highlighting
- TCP stream reassembly (bidirectional, emits on PSH/FIN/RST)
- JSON output (`--json`), hex dump (`-x`), quiet mode (`-q`)
- Case-insensitive (`-i`) and inverted (`-v`) matching
- Interface listing (`-L`)
- Packet count limit (`-n`)
- HTTP/1.1 and HTTP/2 aware mode (`--http`)
- DNS-aware mode (`--dns`)
- TLS 1.3 decryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) via SSLKEYLOGFILE
- TLS 1.2 AES-GCM and ChaCha20-Poly1305 decryption
- Write matched packets to pcap file (`-O`)
- Interactive TUI mode (`--tui`)
- Line-buffered output (`-l`)
- Kernel buffer size option (`-B`)
