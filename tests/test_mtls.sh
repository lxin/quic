#!/bin/sh
# ==========================================================================
# Test script for QUIC mutual TLS (mTLS) and custom CA authentication
# ==========================================================================

set -eu

MTLS_TEST="${1:-./mtls_test}"
PORT="${2:-12345}"

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'quic_mtls_test')
SERVER_PID=""

cleanup() {
	if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
		kill -TERM "${SERVER_PID}" 2>/dev/null || true
		wait "${SERVER_PID}" 2>/dev/null || true
	fi
	rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

# 1. Generate trusted Root CA, Server Certificate, and Client Certificate
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout "${TMP_DIR}/ca.key" -out "${TMP_DIR}/ca.crt" \
	-subj "/CN=LibQUICTestCA" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
	-keyout "${TMP_DIR}/server.key" -out "${TMP_DIR}/server.csr" \
	-subj "/CN=localhost" 2>/dev/null
cat <<EOF >"${TMP_DIR}/server.cnf"
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in "${TMP_DIR}/server.csr" -CA "${TMP_DIR}/ca.crt" -CAkey "${TMP_DIR}/ca.key" \
	-CAcreateserial -out "${TMP_DIR}/server.crt" -days 1 \
	-extfile "${TMP_DIR}/server.cnf" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
	-keyout "${TMP_DIR}/client.key" -out "${TMP_DIR}/client.csr" \
	-subj "/CN=LibQUICTestClient" 2>/dev/null
cat <<EOF >"${TMP_DIR}/client.cnf"
extendedKeyUsage = clientAuth
EOF
openssl x509 -req -in "${TMP_DIR}/client.csr" -CA "${TMP_DIR}/ca.crt" -CAkey "${TMP_DIR}/ca.key" \
	-CAcreateserial -out "${TMP_DIR}/client.crt" -days 1 \
	-extfile "${TMP_DIR}/client.cnf" 2>/dev/null

# 2. Generate an untrusted rogue CA and rogue client certificate
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout "${TMP_DIR}/rogue_ca.key" -out "${TMP_DIR}/rogue_ca.crt" \
	-subj "/CN=RogueCA" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
	-keyout "${TMP_DIR}/rogue_client.key" -out "${TMP_DIR}/rogue_client.csr" \
	-subj "/CN=RogueClient" 2>/dev/null
openssl x509 -req -in "${TMP_DIR}/rogue_client.csr" -CA "${TMP_DIR}/rogue_ca.crt" -CAkey "${TMP_DIR}/rogue_ca.key" \
	-CAcreateserial -out "${TMP_DIR}/rogue_client.crt" -days 1 \
	-extfile "${TMP_DIR}/client.cnf" 2>/dev/null

echo "=== Case 1: Valid mTLS handshake and data exchange (IPv4) ==="
"${MTLS_TEST}" server 127.0.0.1 "${PORT}" \
	"${TMP_DIR}/server.key" "${TMP_DIR}/server.crt" "${TMP_DIR}/ca.crt" &
SERVER_PID=$!
sleep 1
"${MTLS_TEST}" client 127.0.0.1 "${PORT}" localhost \
	"${TMP_DIR}/ca.crt" "${TMP_DIR}/client.crt" "${TMP_DIR}/client.key"
wait "${SERVER_PID}"
SERVER_PID=""

echo "=== Case 2: Valid mTLS handshake and data exchange (IPv6) ==="
PORT_V6=$((PORT + 1))
"${MTLS_TEST}" server ::1 "${PORT_V6}" \
	"${TMP_DIR}/server.key" "${TMP_DIR}/server.crt" "${TMP_DIR}/ca.crt" &
SERVER_PID=$!
sleep 1
"${MTLS_TEST}" client ::1 "${PORT_V6}" localhost \
	"${TMP_DIR}/ca.crt" "${TMP_DIR}/client.crt" "${TMP_DIR}/client.key"
wait "${SERVER_PID}"
SERVER_PID=""

echo "=== Case 3: Negative test - missing client certificate must fail ==="
PORT_NEG1=$((PORT + 2))
"${MTLS_TEST}" server 127.0.0.1 "${PORT_NEG1}" \
	"${TMP_DIR}/server.key" "${TMP_DIR}/server.crt" "${TMP_DIR}/ca.crt" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1
if "${MTLS_TEST}" client 127.0.0.1 "${PORT_NEG1}" localhost "${TMP_DIR}/ca.crt" >/dev/null 2>&1; then
	echo "FAIL: Client without certificate unexpectedly succeeded!" >&2
	exit 1
fi
kill -TERM "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""

echo "=== Case 4: Negative test - untrusted client certificate must fail ==="
PORT_NEG2=$((PORT + 3))
"${MTLS_TEST}" server 127.0.0.1 "${PORT_NEG2}" \
	"${TMP_DIR}/server.key" "${TMP_DIR}/server.crt" "${TMP_DIR}/ca.crt" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1
if "${MTLS_TEST}" client 127.0.0.1 "${PORT_NEG2}" localhost \
	"${TMP_DIR}/ca.crt" "${TMP_DIR}/rogue_client.crt" "${TMP_DIR}/rogue_client.key" >/dev/null 2>&1; then
	echo "FAIL: Client with untrusted certificate unexpectedly succeeded!" >&2
	exit 1
fi
kill -TERM "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
SERVER_PID=""

echo "PASS: All QUIC mTLS tests passed."
