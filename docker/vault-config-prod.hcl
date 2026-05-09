# HashiCorp Vault — Production Configuration
#
# IMPORTANT: This file is a template. Replace all CHANGE_ME values
# with actual paths/values before deploying to production.
# Never commit actual certificates or keys to version control.

storage "postgresql" {
  connection_url = "postgres://${VAULT_DB_USER}:${VAULT_DB_PASSWORD}@${VAULT_DB_HOST}:5432/vault?sslmode=require"
  table          = "vault_kv_store"
  ha_enabled     = "true"
  ha_table       = "vault_ha_locks"
}

listener "tcp" {
  address            = "0.0.0.0:8200"
  tls_disable        = false
  tls_cert_file      = "/vault/tls/vault.crt"
  tls_key_file       = "/vault/tls/vault.key"
  tls_client_ca_file = "/vault/tls/ca.crt"
  # Require mTLS for all connections (production scope)
  tls_require_and_verify_client_cert = true
  tls_min_version    = "tls13"
}

# Seal configuration — use cloud KMS for auto-unseal
# Uncomment and configure the appropriate seal for your cloud provider:

# AWS KMS auto-unseal
# seal "awskms" {
#   region     = "eu-west-1"
#   kms_key_id = "CHANGE_ME_kms_key_arn"
# }

# Azure Key Vault auto-unseal
# seal "azurekeyvault" {
#   tenant_id      = "CHANGE_ME"
#   client_id      = "CHANGE_ME"
#   client_secret  = "CHANGE_ME"
#   vault_name     = "CHANGE_ME"
#   key_name       = "CHANGE_ME"
# }

api_addr     = "https://${VAULT_HOSTNAME}:8200"
cluster_addr = "https://${VAULT_HOSTNAME}:8201"
ui           = false

# Audit logging
# Enable after initialisation with: vault audit enable file file_path=/vault/logs/audit.log
