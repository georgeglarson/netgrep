# netgrep

[![CI](https://github.com/georgeglarson/netgrep/actions/workflows/ci.yml/badge.svg)](https://github.com/georgeglarson/netgrep/actions/workflows/ci.yml)

**Grep for the network, for a post-TLS world.**

A modern replacement for [ngrep](https://github.com/jpr5/ngrep) with TCP stream reassembly, TLS decryption, and protocol-aware matching. Fills the gap between `ngrep` (too simple) and `tshark` (too heavy).

## Features

- **Live capture & pcap replay** — capture from any interface or read pcap/pcapng files
- **BPF filters** — standard tcpdump filter syntax (`-F "tcp port 443"`)
- **Regex matching** — match against reassembled payloads with color highlighting
- **TCP stream reassembly** — bidirectional, with reorder handling (the killer feature)
- **TLS 1.2 & 1.3 decryption** — AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 via SSLKEYLOGFILE
- **HTTP/1.1 & HTTP/2** — parse headers, methods, status codes; HTTP/2 auto-detected via connection preface
- **DNS awareness** — parse queries/responses, match against domain names and record data
- **Interactive TUI** — packet table + detail pane + status bar (ratatui)
- **Multiple output formats** — colored text, JSON (`--json`), hex dump (`-x`)
- **Pcap output** — write matched packets to pcap file (`-O`)
- **ngrep-compatible flags** — `-i`, `-v`, `-x`, `-q`, `-n`, `-d`, `-I`, `-F`

## Installation

### Prerequisites

- Rust 1.85+ (edition 2024)
- `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (RHEL/Fedora)
- Root/sudo for live capture

### Build from source

```bash
# Install libpcap development headers
sudo apt install libpcap-dev   # Debian/Ubuntu
sudo dnf install libpcap-devel # Fedora/RHEL

# Build and install
cargo install --path .
```

## Usage

```bash
# Capture 5 streams/packets
sudo netgrep -n 5

# Grep DNS traffic for a pattern
sudo netgrep -F "udp port 53" "lastpass"

# Search a pcap file for passwords
netgrep -I capture.pcap "password"

# HTTP-aware mode with TLS decryption
sudo netgrep --http --keylog /path/to/sslkeylog.txt "Set-Cookie"

# DNS mode
sudo netgrep --dns -F "udp port 53" "example\\.com"

# Interactive TUI mode
sudo netgrep --tui

# JSON output, case-insensitive
sudo netgrep --json -i "api[_-]key"
```

## Flags

| Flag | Long | Description |
|------|------|-------------|
| | `PATTERN` | Regex pattern to match against payloads |
| `-F` | `--bpf` | BPF filter expression (tcpdump syntax) |
| `-d` | `--interface` | Network interface to capture on |
| `-I` | `--input` | Read from pcap/pcapng file |
| `-i` | `--ignore-case` | Case-insensitive matching |
| `-v` | `--invert` | Invert match (show non-matching) |
| | `--json` | Output as JSON |
| `-n` | `--count` | Capture N matches then exit |
| `-p` | `--no-promisc` | Don't use promiscuous mode |
| | `--no-reassemble` | Disable TCP stream reassembly |
| `-x` | `--hex` | Show hex dump of payloads |
| | `--http` | HTTP-aware mode (parse headers, methods) |
| | `--dns` | DNS-aware mode (parse queries/responses) |
| | `--keylog` | SSLKEYLOGFILE path for TLS decryption |
| `-q` | `--quiet` | Quiet mode (payload only) |
| `-L` | `--list-interfaces` | List available interfaces |
| `-s` | `--snaplen` | Snap length (default: 65535) |
| `-O` | `--output-file` | Write matched packets to pcap file |
| | `--tui` | Interactive TUI mode |
| `-B` | `--buffer-size` | Kernel buffer size in KiB |
| `-l` | `--line-buffered` | Flush stdout after each match |

## Architecture

```
src/
├── main.rs             # CLI definition (clap), main capture loop
├── capture/mod.rs      # PacketSource: live capture + pcap file reading
├── protocol/
│   ├── mod.rs          # Packet parsing, Transport enum, StreamKey
│   ├── dns.rs          # DNS query/response parser
│   ├── http.rs         # HTTP/1.1 request/response parser
│   └── http2.rs        # HTTP/2 frame parser + HPACK decoder
├── reassembly/mod.rs   # TCP stream reassembly (emits on PSH/FIN/RST)
├── output/mod.rs       # Formatter: text, JSON, hex dump, HTTP mode
├── tls/
│   ├── mod.rs          # TLS decryptor: per-connection state machine
│   ├── keylog.rs       # SSLKEYLOGFILE parser (TLS 1.2 + 1.3)
│   └── decrypt.rs      # AES-GCM/ChaCha20 decryption, HKDF, TLS PRF
└── tui/
    ├── mod.rs          # TUI mode: event loop, rendering (ratatui)
    └── event.rs        # Data types for TUI display
```

## License

MIT — see [LICENSE](LICENSE) for details.
