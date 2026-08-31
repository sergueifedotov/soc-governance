#!/bin/sh
# Generates self-signed TLS certificates for all Wazuh components.
# Output directory: /certificates (bind-mounted from ./config/wazuh_indexer_ssl_certs/)
set -e

apk add --no-cache openssl > /dev/null 2>&1

D=/certificates
SUBJ_BASE="/C=US/ST=California/L=California/O=Wazuh/OU=Wazuh"
DAYS=3650

# Skip if certs already exist (idempotent)
if [ -f "$D/root-ca.pem" ]; then
  echo "Certificates already exist — skipping generation."
  exit 0
fi

echo "Generating Wazuh TLS certificates..."

# ---------------------------------------------------------------------------
# Root CA
# ---------------------------------------------------------------------------
openssl genrsa -out "$D/root-ca-key.pem" 2048 2>/dev/null
openssl req -new -x509 -days $DAYS \
  -key  "$D/root-ca-key.pem" \
  -out  "$D/root-ca.pem" \
  -subj "$SUBJ_BASE/CN=Root CA" 2>/dev/null
# Manager uses a copy of the root CA (Filebeat trust anchor)
cp "$D/root-ca.pem" "$D/root-ca-manager.pem"
echo "  [ok] root-ca.pem"

# ---------------------------------------------------------------------------
# Helper: issue a cert signed by the root CA
# Usage: gen_cert <filename-base> <CN> <SAN-value>
# ---------------------------------------------------------------------------
gen_cert() {
  local name="$1" cn="$2" san="$3"

  openssl genrsa -out "$D/${name}-key.pem" 2048 2>/dev/null

  openssl req -new \
    -key  "$D/${name}-key.pem" \
    -out  "$D/${name}.csr" \
    -subj "$SUBJ_BASE/CN=$cn" 2>/dev/null

  printf 'subjectAltName=%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n' \
    "$san" > /tmp/ext.cnf

  openssl x509 -req -days $DAYS \
    -in      "$D/${name}.csr" \
    -CA      "$D/root-ca.pem" \
    -CAkey   "$D/root-ca-key.pem" \
    -CAcreateserial \
    -out     "$D/${name}.pem" \
    -extfile /tmp/ext.cnf 2>/dev/null

  rm -f "$D/${name}.csr"
  echo "  [ok] ${name}.pem"
}

# Admin cert — used by the indexer security plugin for admin operations
gen_cert "admin"          "admin"           "DNS:admin"

# Wazuh Indexer (OpenSearch node)
gen_cert "wazuh.indexer"  "wazuh.indexer"   "DNS:wazuh.indexer,IP:127.0.0.1"

# Wazuh Manager (Filebeat client cert)
gen_cert "wazuh.manager"  "wazuh.manager"   "DNS:wazuh.manager,IP:127.0.0.1"

# Wazuh Dashboard
gen_cert "wazuh.dashboard" "wazuh.dashboard" "DNS:wazuh.dashboard,IP:127.0.0.1"

# Ensure all certs are world-readable inside containers
chmod 644 "$D"/*.pem

echo "Certificate generation complete."
