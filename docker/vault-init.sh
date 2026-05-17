#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Vault bootstrap script — runs once at docker compose up
#
# Activates the Transit secrets engine and creates the PCM bootstrap key
# so the application can start without any manual Vault configuration.
#
# Idempotent: safe to run multiple times (already-enabled engines are skipped).
# ─────────────────────────────────────────────────────────────────────────────

set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

echo "[vault-init] Waiting for Vault to be ready at ${VAULT_ADDR}..."
until vault status > /dev/null 2>&1; do
  sleep 2
done
echo "[vault-init] Vault is ready."

# ── Enable Transit secrets engine (idempotent) ────────────────────────────────
if vault secrets list | grep -q "^transit/"; then
  echo "[vault-init] Transit engine already enabled — skipping."
else
  vault secrets enable transit
  echo "[vault-init] Transit engine enabled."
fi

# ── Enable KV v2 secrets engine (idempotent) ─────────────────────────────────
if vault secrets list | grep -q "^secret/"; then
  echo "[vault-init] KV v2 engine already enabled — skipping."
else
  vault secrets enable -path=secret kv-v2
  echo "[vault-init] KV v2 engine enabled."
fi

# ── Create the PCM health-check key (idempotent) ─────────────────────────────
if vault read transit/keys/pcm-bootstrap > /dev/null 2>&1; then
  echo "[vault-init] pcm-bootstrap key already exists — skipping."
else
  vault write -f transit/keys/pcm-bootstrap type=aes256-gcm96
  echo "[vault-init] pcm-bootstrap key created."
fi

echo "[vault-init] Bootstrap complete. Vault is ready for PCM."
