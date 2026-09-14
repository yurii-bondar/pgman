#!/usr/bin/env bash
#
# Generate a self-signed TLS certificate for local development.
#
# These certificates are for localhost only and are deliberately not
# committed: a private key in version control is compromised the moment
# it is pushed, and no amount of "it's only for dev" changes that.
# Production deployments supply their own pair via tls_cert_file /
# tls_key_file (or terminate TLS upstream).
#
# Usage: scripts/gen-dev-certs.sh [output-dir]   (default: certs)

set -euo pipefail

out_dir="${1:-certs}"
days=365

mkdir -p "$out_dir"

if [[ -e "$out_dir/server.key" ]]; then
	echo "refusing to overwrite existing $out_dir/server.key" >&2
	echo "remove it explicitly if you want a fresh pair" >&2
	exit 1
fi

# subjectAltName is required, not optional: Go's crypto/tls has ignored
# the legacy Common Name fallback since 1.15, so a cert without a SAN is
# rejected by every modern client including psql and pgx.
openssl req -x509 -newkey rsa:2048 -sha256 -days "$days" -nodes \
	-keyout "$out_dir/server.key" \
	-out "$out_dir/server.crt" \
	-subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
	-addext "keyUsage=critical,digitalSignature,keyEncipherment" \
	-addext "extendedKeyUsage=serverAuth" 2>/dev/null

chmod 600 "$out_dir/server.key"
chmod 644 "$out_dir/server.crt"

echo "wrote $out_dir/server.crt and $out_dir/server.key (self-signed, ${days}d, localhost only)"
