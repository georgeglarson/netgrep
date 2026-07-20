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

# Track every spawned process and temp file so a failure at any point (set -e
# aborts mid-capture, e.g. curl fails on a busy port) still tears them down.
# The privileged tcpdump is the one that matters: left running it keeps
# capturing indefinitely.
declare -a BG_PIDS=() SUDO_PIDS=() TMPS=("$CERT" "$KEY")
cleanup() {
  local pid
  for pid in ${SUDO_PIDS[@]+"${SUDO_PIDS[@]}"}; do sudo kill "$pid" 2>/dev/null || true; done
  for pid in ${BG_PIDS[@]+"${BG_PIDS[@]}"};   do kill "$pid" 2>/dev/null || true; done
  rm -f ${TMPS[@]+"${TMPS[@]}"}
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 3650 \
  -nodes -subj "/CN=localhost" 2>/dev/null

# $1=tls-flag  $2=curl-flags  $3=marker  $4=basename
capture() {
  local tlsflag="$1" curlflags="$2" marker="$3" base="$4" port=$((8600 + RANDOM % 400))
  local err; err=$(mktemp); TMPS+=("$err")

  openssl s_server -accept "$port" -cert "$CERT" -key "$KEY" -www "$tlsflag" -quiet >/dev/null 2>&1 &
  local srv=$!; BG_PIDS+=("$srv")

  sudo tcpdump -i lo -U -w "$base.pcap" "tcp port $port" 2>"$err" &
  local td=$!; SUDO_PIDS+=("$td")
  # Wait for tcpdump to actually be listening before generating traffic.
  local _
  for _ in $(seq 1 25); do grep -q listening "$err" 2>/dev/null && break; sleep 0.2; done

  # Confirm OUR s_server actually bound the port before generating traffic. Two
  # services can't hold the same port, so if the random port was already taken,
  # s_server failed to bind and exited — catch that here rather than let curl
  # (-k) talk to the foreign squatter and capture someone else's session.
  sleep 0.3
  if ! kill -0 "$srv" 2>/dev/null; then
    echo "ERROR: openssl s_server for $base is not running — port $port already in use?" >&2
    return 1
  fi

  # curl opens SSLKEYLOGFILE in append mode, so truncate first — otherwise a
  # re-run leaves the keylog holding every prior run's secrets and it stops
  # being a faithful pairing with the freshly-captured pcap.
  : > "$base.keys"

  # --retry-connrefused rides out the server not being bound yet without a
  # separate readiness poll; a refused connection produces no TLS records, so
  # the capture and keylog stay clean. Capture curl's exit rather than let it
  # abort mid-function (set -e) — a nonzero rc means the port was held by a
  # foreign service or the handshake failed, i.e. a bad fixture.
  # $curlflags is intentionally unquoted: it must word-split ("--tlsv1.2" ->
  # one flag) or vanish entirely when empty, which "$curlflags" would not do.
  local curl_rc=0
  # shellcheck disable=SC2086
  SSLKEYLOGFILE="$base.keys" curl -sk --retry 5 --retry-connrefused --retry-delay 1 \
    $curlflags "https://localhost:$port/$marker" >/dev/null 2>&1 || curl_rc=$?

  sleep 1
  sudo kill -INT "$td" 2>/dev/null || true; sleep 0.3
  kill "$srv" 2>/dev/null || true
  wait 2>/dev/null || true
  # These PIDs are now reaped; drop them so the EXIT trap can't signal a reused
  # PID on a later capture. cert/key temps stay tracked for the final cleanup.
  BG_PIDS=(); SUDO_PIDS=()
  # Always chown, even on a failed run, so tcpdump never leaves a root-owned
  # pcap in the tree for the next non-sudo invocation to trip over.
  sudo chown "$(id -u):$(id -g)" "$base.pcap" 2>/dev/null || true

  # Fail loud rather than commit a silently-bad capture: curl error (port held
  # by something else), an empty/garbage pcap, or an empty keylog.
  if [ "$curl_rc" -ne 0 ]; then
    echo "ERROR: curl failed (rc=$curl_rc) for $base — port $port held by another service?" >&2
    return 1
  fi
  if [ ! -s "$base.pcap" ] || [ "$(wc -c <"$base.pcap")" -lt 500 ]; then
    echo "ERROR: $base.pcap is empty or too small — capture failed (port $port busy?)." >&2
    return 1
  fi
  # A curl built against a TLS backend that ignores SSLKEYLOGFILE exits 0 with a
  # perfectly good pcap and an empty keylog — a silently-useless fixture that
  # would only surface later as a mystifying tls_e2e failure. Catch it now.
  if [ ! -s "$base.keys" ]; then
    echo "ERROR: $base.keys is empty — curl's TLS backend ignored SSLKEYLOGFILE." >&2
    return 1
  fi
  echo "wrote $base.pcap ($(wc -c <"$base.pcap") bytes) + $base.keys"
}

# TLS 1.3: client and server both speak 1.3.
capture -tls1_3 "" "netgrep-tls13-marker-7Qx" tls13_aesgcm
# TLS 1.2: client offers 1.3 (default modern behavior) but server forces 1.2 —
# the exact real-world shape that regressed before the ServerHello-negotiation fix.
capture -tls1_2 "--tlsv1.2" "netgrep-tls12-marker-4Rk" tls12_ecdhe_rsa_aesgcm
