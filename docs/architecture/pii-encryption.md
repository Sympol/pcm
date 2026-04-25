# PII Encryption Architecture

This document describes the encryption architecture used in PCM to protect Personally
Identifiable Information (PII) at rest. It covers the envelope encryption pattern,
key hierarchy, ciphertext format, and IV generation strategy.

---

## 1. Envelope Encryption Pattern

PCM uses **envelope encryption** (the KEK/DEK pattern) to balance security and
performance:

- **Data Encryption Keys (DEKs)** encrypt the actual PII data using AES-256-GCM.
- **Key Encryption Keys (KEKs)** encrypt the DEKs and are stored exclusively in the
  KMS/HSM — they never leave the secure boundary.
- Decrypted DEKs are cached in application memory (LRU, TTL = 1 hour, max 1 000 entries)
  to avoid a KMS round-trip on every field access.

```
┌─────────────────────────────────────────────────────────────────┐
│  KMS / HSM  (secure boundary — KEKs never leave)               │
│                                                                 │
│  KEK_PROFILE   KEK_CONSENT   KEK_SEGMENT   KEK_PREFERENCE       │
└────────┬──────────────┬──────────────────────────────────────── ┘
         │ encrypts     │ encrypts
         ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Application Memory  (DEK cache — decrypted DEKs, TTL 1 h)     │
│                                                                 │
│  DEK-A (Profile context)    DEK-B (Consent context)            │
│  DEK-C (per-user, Profile)  …                                   │
└────────┬──────────────┬──────────────────────────────────────── ┘
         │ encrypts     │ encrypts
         ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Database  (ciphertext only — no plaintext PII ever stored)     │
└─────────────────────────────────────────────────────────────────┘
```

### Encryption flow (single field)

1. Domain layer calls `IEncryptionService.encrypt(plaintext, context)`.
2. `EncryptionService` asks `KeyManager` for the active DEK for the context.
3. `KeyManager` checks the in-memory DEK cache. On a miss it calls the KMS to decrypt
   the stored encrypted DEK, then caches the result.
4. `EncryptionService` generates a unique 96-bit IV (see §4).
5. AES-256-GCM encryption is performed with the DEK and IV.
6. The result is serialised into the binary ciphertext format (see §3).
7. The audit logger records the operation (no plaintext, no key material).
8. The ciphertext is returned to the infrastructure layer for database storage.

### Decryption flow (single field)

1. Domain layer calls `IEncryptionService.decrypt(ciphertext, context)`.
2. `EncryptionService` parses the ciphertext to extract `key_id`, `algorithm_id`, and `IV`.
3. `KeyManager` retrieves the DEK identified by `key_id` (cache-first).
4. AES-256-GCM decryption is performed; the authentication tag is verified.
5. Plaintext is returned. Any tampering causes an immediate error.

---

## 2. Key Hierarchy

### Namespace format

Every key is identified by a structured namespace:

```
{environment}.{bounded_context}.{key_type}.{key_id}
```

Examples:
```
prod.profile.kek.550e8400-e29b-41d4-a716-446655440000
prod.profile.dek.context.6ba7b810-9dad-11d1-80b4-00c04fd430c8
prod.consent.dek.user.a1b2c3d4-...
```

### Key types

| Type | Scope | Stored in | Cached |
|------|-------|-----------|--------|
| KEK | Per bounded context × environment | KMS/HSM only | Never |
| DEK (context) | Per bounded context | KMS (encrypted by KEK) | Yes (1 h TTL) |
| DEK (user) | Per user (for cryptographic erasure) | KMS (encrypted by KEK) | Yes (1 h TTL) |
| Blind index key | Global | KMS | Yes |

### Context isolation

Each of the four bounded contexts — **Profile**, **Consent**, **Segment**, and
**Preference** — has its own KEK. A compromise of one context's KEK does not affect
the others.

### Environment isolation

DEV, STAGING, and PROD each have separate root KEKs stored in separate KMS namespaces.
The `KeyManager` verifies the environment identifier in key metadata on every load and
rejects keys from a different environment, logging a `SECURITY_EVENT`.

### Key rotation triggers

| Trigger | DEK | KEK |
|---------|-----|-----|
| Time | 90 days | 365 days |
| Volume | 1 TB encrypted | — |
| Operations | 2³² encryptions | — |
| IV counter overflow | Automatic (before 2³²) | — |
| Suspected compromise | Emergency (≤ 15 min) | On demand |

---

## 3. Ciphertext Format

Every encrypted field is stored as a self-describing binary blob:

```
┌─────────┬──────────┬──────────────────┬────────────┬─────────────┬──────────┐
│ Version │  Alg ID  │     Key ID       │     IV     │ Ciphertext  │   Tag    │
│ 1 byte  │  1 byte  │   16 bytes       │  12 bytes  │   N bytes   │ 16 bytes │
└─────────┴──────────┴──────────────────┴────────────┴─────────────┴──────────┘
  byte 0    byte 1     bytes 2–17         bytes 18–29  bytes 30–…   last 16 B
```

| Field | Value | Notes |
|-------|-------|-------|
| Version | `0x01` | Current format version |
| Algorithm ID | `0x01` = AES-256-GCM, `0x02` = AES-256-CBC+HMAC | Selects decryption path |
| Key ID | 128-bit UUID, big-endian | Identifies the DEK |
| IV | 96-bit counter-based IV | See §4 |
| Ciphertext | Variable | AES-256-GCM output |
| Authentication Tag | 16 bytes | GCM tag; detects tampering |

**Total overhead:** 46 bytes + plaintext length.

The format is self-describing: the `key_id` and `algorithm_id` embedded in every
ciphertext allow decryption of historical data after key rotation or algorithm
migration without any external lookup.

---

## 4. Counter-Based IV Generation

AES-256-GCM requires a unique IV for every encryption with the same key. PCM uses a
**counter-based** approach rather than pure random generation to provide a stronger
uniqueness guarantee:

```
IV (96 bits) = random_base (64 bits) || counter (32 bits)
```

- `random_base` is generated once per DEK using `SecureRandom` and stored with the
  counter state.
- `counter` is a monotonically increasing 32-bit integer, incremented on every
  encryption.
- The counter state is persisted to durable storage every **1 000 increments** to
  survive application restarts without IV reuse.
- When the counter approaches **2³¹** (half of the 32-bit range), automatic DEK
  rotation is triggered before overflow can occur.
- If rotation cannot complete before overflow, new encryption operations are rejected
  until rotation succeeds.

This design guarantees IV uniqueness within a DEK's lifetime while tolerating
application restarts.

---

## 5. Searchable Encryption (Blind Indexing)

Encrypted fields cannot be searched directly. PCM uses **blind indexing** to support
exact-match queries without decrypting data:

```
blind_index = HMAC-SHA256(
    key  : blind_index_key,
    data : global_salt || record_salt || normalize(plaintext)
)
```

- `blind_index_key` is a separate key stored in the KMS.
- `global_salt` is a secret shared across all records (resists frequency analysis).
- `record_salt` is unique per record (resists pattern matching — identical values in
  different records produce different blind indexes).
- `normalize` lowercases and trims the input for case-insensitive matching.

The blind index is stored in a dedicated column (e.g., `handle_blind_index`) and
indexed for fast lookup. Partial-match searching is not supported for encrypted fields.

---

## 6. Architecture Decision Records

- [ADR-001: Hexagonal Architecture](adr-001-hexagonal-architecture.md) — why the
  domain layer is framework-agnostic and encryption is an infrastructure concern.
- [ADR-003: Infrastructure Abstraction](adr-003-infrastructure-abstraction.md) —
  how infrastructure adapters are wired without polluting the domain.
