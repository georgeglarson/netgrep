# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Please report security vulnerabilities through [GitHub Security Advisories](https://github.com/georgeglarson/netgrep/security/advisories/new).

Do **not** open a public issue for security vulnerabilities.

You should receive a response within 72 hours. If confirmed, a fix will be prioritized and released as a patch version.

## Security Considerations

- **Root/sudo required for live capture:** netgrep uses libpcap for packet capture, which requires elevated privileges. Use the minimum necessary permissions.
- **TLS key material:** When using `--keylog`, the SSLKEYLOGFILE contains sensitive cryptographic secrets. Ensure it has restrictive file permissions (`chmod 600`). Key material is zeroized on drop.
- **Output files:** The `-O` flag creates pcap output files with mode `0600` (owner read/write only) and refuses to overwrite existing files.
