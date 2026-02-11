# netgrep

Grep for the network, for a post-TLS world — with AI superpowers when you want them.

## What This Is

A modern replacement for ngrep (not a fork). ngrep is alive but architecturally frozen: single-packet matching, no TLS, no stream reassembly, no protocol awareness. netgrep fills the gap between `ngrep` (too simple) and `tshark` (too heavy).

## Tech Stack

- **Language:** Rust (edition 2024)
- **Capture:** `pcap` crate (libpcap bindings)
- **Dissection:** `etherparse` (zero-copy packet parsing)
- **CLI:** `clap` (derive mode)
- **Output:** `colored` for terminal, `serde_json` for JSON
- **Error handling:** `anyhow` + `thiserror`

## Module Layout

```
src/
├── main.rs             # CLI definition (clap), main capture loop, PcapWriter
├── capture/mod.rs      # PacketSource: live capture + pcap file reading
├── protocol/
│   ├── mod.rs          # Packet parsing, Transport enum, StreamKey, TcpFlags
│   ├── dns.rs          # DNS query/response parser (via simple-dns)
│   └── http.rs         # HTTP/1.1 request/response parser
├── reassembly/mod.rs   # StreamTable: TCP stream reassembly (emits on PSH/FIN/RST)
├── output/mod.rs       # Formatter: text (color-highlighted), JSON, hex dump, HTTP mode
└── tls/
    ├── mod.rs          # TlsDecryptor: per-connection state, incremental record parsing
    ├── keylog.rs       # SSLKEYLOGFILE parser (TLS 1.2 + 1.3 secrets)
    └── decrypt.rs      # AES-GCM decryption, HKDF-Expand-Label, TLS 1.2 PRF
```

## What's Implemented (Phase 1 — complete)

- Live capture and pcap/pcapng file reading (pcapng via libpcap native support)
- BPF filter support (`-F`)
- Regex matching against payloads with color highlighting
- TCP stream reassembly (bidirectional, emits on PSH/FIN/RST)
- JSON output (`--json`), hex dump (`-x`), quiet mode (`-q`)
- Case-insensitive (`-i`) and inverted (`-v`) matching
- Interface listing (`-L`)
- Packet count limit (`-n`)
- `--http` flag: HTTP/1.1-aware mode (parse headers, match against fields)
- `--dns` flag: DNS-aware mode (parse queries/responses, match against domain names and record data)
- `--keylog` / `SSLKEYLOGFILE`: TLS 1.3 decryption (AES-128-GCM, AES-256-GCM) — tested
- TLS 1.2 AES-GCM decryption (ECDHE-ECDSA, ECDHE-RSA, RSA key exchange) — tested
- `-O` / `--output-file`: write matched packets to pcap file

## What's Stubbed / Not Yet Implemented

### Phase 2 — AI + polish
- Ollama integration for natural language to BPF filter conversion
- Traffic summarization (`--summarize`)
- HTTP/2 + gRPC protocol support
- Ratatui TUI mode (`--tui`)
- Anomaly flagging
- Container name resolution (Docker/Podman)

### Phase 3 — community
- `--explain` mode (BPF filter to plain English)
- Plugin system for custom protocol parsers
- eBPF capture backend
- MCP server mode

## Key Design Decisions

- **Offline-first AI:** AI features use local models via Ollama. No cloud dependency. Optional cloud API flag for higher quality.
- **Stream reassembly is default:** Unlike ngrep which matches single packets, we reassemble TCP streams before matching. This is the killer feature.
- **ngrep-compatible flags where sensible:** `-i`, `-v`, `-x`, `-q`, `-n`, `-d`, `-I`, `-F` map to familiar ngrep behavior.
- **StreamKey is bidirectional:** Normalized so (A->B) == (B->A) for tracking both sides of a connection.
- **Payload emitted on PSH/FIN/RST:** Stream data is yielded when TCP signals the application layer has data ready, not on every ACK.

## Build & Run

```bash
cargo build
sudo ./target/debug/netgrep -n 5                    # capture 5 streams/packets
sudo ./target/debug/netgrep -F "udp port 53" "lastpass"  # grep DNS for a pattern
sudo ./target/debug/netgrep -I capture.pcap "password"   # search a pcap file
```

Requires `libpcap-dev` and root/sudo for live capture.

## Conventions

- **Single Responsibility Principle:** each module owns one concern. When a file accumulates multiple responsibilities, extract the distinct concern into its own module.
- Keep modules focused: one concern per module
- Use `anyhow::Result` in application code, `thiserror` for library-style errors
- Prefer `etherparse` Slice types (zero-copy) over owned Header types
- No unnecessary abstractions — three similar lines > premature helper function
