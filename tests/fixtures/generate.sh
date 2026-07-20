#!/usr/bin/env bash
# Regenerate the TLS end-to-end decryption fixtures used by tests/tls_e2e.rs.
#
# Each fixture is a real, locally-captured TLS session (loopback, throwaway
# self-signed cert) plus its SSLKEYLOGFILE. netgrep decrypts the capture with
# the keylog and greps a marker string that exists ONLY inside the encrypted
# payload — proving decryption end to end, not just against synthetic vectors.
#
# The keylogs hold secrets for ephemeral localhost sessions to a self-signed
# cert; they protect nothing and are safe to commit as test data.
#
# Requires: openssl, curl (built against OpenSSL/GnuTLS so SSLKEYLOGFILE works),
# tcpdump with sudo, and a free loopback port. Run from the repo root:
#   sudo -v && tests/fixtures/generate.sh
set -euo pipefail
cd "$(dirname "$0")"

CERT=$(mktemp); KEY=$(mktemp)
trap 'rm -f "$CERT" "$KEY"' EXIT
openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 3650 \
  -nodes -subj "/CN=localhost" 2>/dev/null

# $1=tls-flag  $2=curl-flags  $3=marker  $4=basename
capture() {
  local tlsflag="$1" curlflags="$2" marker="$3" base="$4" port=$((8600 + RANDOM % 400))
  openssl s_server -accept "$port" -cert "$CERT" -key "$KEY" -www "$tlsflag" -quiet >/dev/null 2>&1 &
  local srv=$!; sleep 1
  local err; err=$(mktemp)
  sudo tcpdump -i lo -U -w "$base.pcap" "tcp port $port" 2>"$err" &
  local td=$!
  for _ in $(seq 1 20); do grep -q listening "$err" 2>/dev/null && break; sleep 0.2; done
  SSLKEYLOGFILE="$base.keys" curl -sk $curlflags "https://localhost:$port/$marker" >/dev/null 2>&1
  sleep 1
  sudo kill -INT "$td" 2>/dev/null || true; sleep 0.3; kill "$srv" 2>/dev/null || true
  wait 2>/dev/null || true
  sudo chown "$(id -u):$(id -g)" "$base.pcap"
  rm -f "$err"
  echo "wrote $base.pcap ($(wc -c <"$base.pcap") bytes) + $base.keys"
}

# TLS 1.3: client and server both speak 1.3.
capture -tls1_3 "" "netgrep-tls13-marker-7Qx" tls13_aesgcm
# TLS 1.2: client offers 1.3 (default modern behavior) but server forces 1.2 —
# the exact real-world shape that regressed before the ServerHello-negotiation fix.
capture -tls1_2 "--tlsv1.2" "netgrep-tls12-marker-4Rk" tls12_ecdhe_rsa_aesgcm
