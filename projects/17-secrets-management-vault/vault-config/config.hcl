# HashiCorp Vault Production Configuration
# Project: 17-secrets-management-vault
# Reference: https://developer.hashicorp.com/vault/docs/configuration
#
# For local dev, use docker-compose.yml instead.
# This config is for a production-ready deployment.

# ── Storage Backend ───────────────────────────────────────────────────────────
# Use file storage for single-node (dev/staging)
# For HA production: switch to raft (integrated) or DynamoDB
storage "file" {
  path = "/vault/data"
}

# For Raft HA (recommended for production):
# storage "raft" {
#   path    = "/vault/data"
#   node_id = "vault-1"
# }

# ── Listener ──────────────────────────────────────────────────────────────────
listener "tcp" {
  address       = "0.0.0.0:8200"
  # In production: enable TLS
  # tls_cert_file = "/vault/tls/server.crt"
  # tls_key_file  = "/vault/tls/server.key"
  tls_disable   = true   # Set to false in production!
  tls_min_version = "tls12"
}

# ── API Address ───────────────────────────────────────────────────────────────
api_addr     = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"

# ── UI ────────────────────────────────────────────────────────────────────────
ui = true

# ── Telemetry ─────────────────────────────────────────────────────────────────
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}

# ── Disable mlock (required in containers; disable on bare metal carefully) ───
disable_mlock = true

# ── Seal Configuration (optional — for auto-unseal with AWS KMS) ──────────────
# seal "awskms" {
#   region     = "us-east-1"
#   kms_key_id = "alias/vault-unseal-key"
# }
