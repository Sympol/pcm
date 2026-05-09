# API Reference

This document provides a comprehensive reference for the PCM (Profile & Consent Manager) REST API, including expected payloads and `curl` examples.

PCM is a **modular monolith** — all bounded contexts are served by a single Spring Boot application on a single port.

## Base URL

| Environment | Base URL |
|-------------|----------|
| Local development | `http://localhost:8080` |
| Docker Compose | `http://localhost:8080` |

---

## Authentication & Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Tenant-Id` | Yes | Tenant identifier. Use `default` for local development. |
| `Authorization` | Production only | `Bearer <JWT>` — Keycloak-issued JWT token. |
| `Content-Type` | POST/PUT/PATCH | `application/json` |

---

## Error Responses

All errors follow [RFC 7807 Problem Details](https://datatracker.ietf.org/doc/html/rfc7807) with `Content-Type: application/problem+json`.

```json
{
  "type": "https://pcm.vibeafrika.dev/errors/not-found",
  "title": "Resource Not Found",
  "status": 404,
  "detail": "Consent with id '550e8400-...' not found",
  "instance": "/api/v1/consents/550e8400-...",
  "timestamp": "2026-04-25T10:00:00Z"
}
```

---

## 1. Profile API

### Create a Profile

**`POST /api/v1/profiles`**

Creates a new user profile. The `handle` must be unique per tenant (3–30 lowercase alphanumeric characters).

**Request body:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "handle": "jdoe",
  "attributes": {
    "fullName": "John Doe",
    "email": "john.doe@example.com",
    "country": "FR"
  }
}
```

**Response:** `201 Created`
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "handle": "jdoe",
  "tenantId": "default",
  "attributes": { "fullName": "John Doe", "email": "john.doe@example.com", "country": "FR" },
  "deleted": false,
  "createdAt": "2026-04-25T10:00:00Z",
  "updatedAt": "2026-04-25T10:00:00Z",
  "version": 0
}
```

```bash
curl -X POST http://localhost:8080/api/v1/profiles \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: default" \
  -d '{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "handle": "jdoe",
    "attributes": { "fullName": "John Doe", "email": "john.doe@example.com" }
  }'
```

---

### Get a Profile

**`GET /api/v1/profiles/{id}`**

Retrieves a profile by ID. Encrypted PII attributes are decrypted automatically.

**Response:** `200 OK` — same shape as Create response.

```bash
curl http://localhost:8080/api/v1/profiles/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-Tenant-Id: default"
```

**Error codes:** `404 Not Found` if the profile does not exist, `410 Gone` if the profile has been erased.

---

### Update a Profile

**`PUT /api/v1/profiles/{id}`**

Updates the profile's attributes. Cannot update a deleted profile.

**Request body:**
```json
{
  "attributes": {
    "fullName": "John Doe Jr.",
    "country": "BE"
  }
}
```

**Response:** `200 OK`

```bash
curl -X PUT http://localhost:8080/api/v1/profiles/550e8400-e29b-41d4-a716-446655440000 \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: default" \
  -d '{"attributes": {"country": "BE"}}'
```

---

### Erase a Profile (GDPR Right to Erasure)

**`DELETE /api/v1/profiles/{id}`**

Anonymizes the profile handle, clears all PII attributes, and marks the profile as deleted. Triggers cryptographic erasure of the user's DEK.

**Response:** `200 OK`

```bash
curl -X DELETE http://localhost:8080/api/v1/profiles/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-Tenant-Id: default"
```

---

### Export Profile Data (GDPR Right to Data Portability)

**`GET /api/v1/profiles/{id}/export`**

Exports all personal data held by PCM for a given profile in a structured, machine-readable format (JSON). 

The export includes data from all bounded contexts:
- **Profile**: Handle, attributes, timestamps
- **Consent**: All consent records with full event history
- **Preference**: All preference settings
- **Segment**: Segment memberships (if applicable)

**Response:** `200 OK`
```json
{
  "profileId": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "default",
  "exportedAt": "2026-04-25T10:00:00Z",
  "profile": {
    "handle": "jdoe",
    "attributes": {
      "fullName": "John Doe",
      "email": "john.doe@example.com",
      "country": "FR"
    },
    "createdAt": "2026-04-25T10:00:00Z",
    "updatedAt": "2026-04-25T10:00:00Z"
  },
  "consents": [
    {
      "consentId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "purpose": "MARKETING",
      "scope": "EMAIL",
      "status": "GRANTED",
      "createdAt": "2026-04-25T10:00:00Z",
      "updatedAt": "2026-04-25T10:00:00Z",
      "events": [
        {
          "status": "GRANTED",
          "timestamp": "2026-04-25T10:00:00Z"
        }
      ]
    }
  ],
  "preferences": [
    {
      "preferenceId": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "settings": {
        "ui.theme": "dark",
        "notifications.email": true
      },
      "createdAt": "2026-04-25T10:00:00Z",
      "updatedAt": "2026-04-25T10:00:00Z"
    }
  ]
}
```

```bash
curl http://localhost:8080/api/v1/profiles/550e8400-e29b-41d4-a716-446655440000/export \
  -H "X-Tenant-Id: default"
```

**Error codes:** 
- `404 Not Found` if the profile does not exist
- `410 Gone` if the profile has been erased

**Compliance Notes:**
- All PII is decrypted before export (user receives their data in clear text)
- Export includes complete audit trail (consent events with timestamps)
- Format is JSON (structured, commonly used, machine-readable)

---

## 2. Consent API

The consent context implements an **immutable ledger** — every grant and revoke is recorded as an append-only event with a cryptographic proof hash.

### Grant Consent

**`POST /api/v1/consents`**

Records a positive consent action in the ledger.

**Request body:**
```json
{
  "profileId": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "default",
  "purpose": "MARKETING",
  "scope": "EMAIL"
}
```

**Response:** `201 Created`
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "profileId": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "default",
  "purpose": "MARKETING",
  "scope": "EMAIL",
  "status": "GRANTED",
  "createdAt": "2026-04-25T10:00:00Z",
  "updatedAt": "2026-04-25T10:00:00Z",
  "version": 0
}
```

```bash
curl -X POST http://localhost:8080/api/v1/consents \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: default" \
  -d '{
    "profileId": "550e8400-e29b-41d4-a716-446655440000",
    "tenantId": "default",
    "purpose": "MARKETING",
    "scope": "EMAIL"
  }'
```

---

### Revoke Consent

**`DELETE /api/v1/consents/{id}`**

Records a revocation event in the ledger. The consent record is not deleted — the ledger is immutable.

**Response:** `200 OK` — `ConsentResponse` with `status: "REVOKED"`.

```bash
curl -X DELETE http://localhost:8080/api/v1/consents/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "X-Tenant-Id: default"
```

---

### Verify Consent

**`GET /api/v1/consents/verify?consentId={id}`**

Returns `true` if the consent is currently active (granted and not revoked), `false` otherwise.

**Response:** `200 OK` — `true` or `false`

```bash
curl "http://localhost:8080/api/v1/consents/verify?consentId=a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -H "X-Tenant-Id: default"
```

---

### Get Consent History

**`GET /api/v1/consents/history?consentId={id}`**

Returns the full immutable ledger for a consent, including all grant and revoke events with timestamps and cryptographic proof hashes.

**Response:** `200 OK`
```json
{
  "consentId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "events": [
    {
      "eventType": "GRANTED",
      "timestamp": "2026-04-25T10:00:00Z",
      "proofHash": "sha256:abc123..."
    },
    {
      "eventType": "REVOKED",
      "timestamp": "2026-04-25T11:00:00Z",
      "proofHash": "sha256:def456..."
    }
  ]
}
```

```bash
curl "http://localhost:8080/api/v1/consents/history?consentId=a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -H "X-Tenant-Id: default"
```

> **TCF Support**: IAB TCF 2.x support is available as a separate module (`pcm-tcf-adapter`). See [ADR-004](architecture/adr-004-tcf-removal.md) for the rationale.

---

## 3. Preference API

### Create Preferences

**`POST /api/v1/preferences`**

Creates a preference record for a profile.

**Request body:**
```json
{
  "profileId": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "default",
  "key": "ui.theme",
  "value": "dark"
}
```

**Response:** `201 Created`

```bash
curl -X POST http://localhost:8080/api/v1/preferences \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: default" \
  -d '{"profileId": "550e8400-...", "tenantId": "default", "key": "ui.theme", "value": "dark"}'
```

---

### Get Preferences

**`GET /api/v1/preferences/{id}`**

Retrieves a preference record by ID.

**Response:** `200 OK`

```bash
curl http://localhost:8080/api/v1/preferences/{id} \
  -H "X-Tenant-Id: default"
```

---

### Update Preferences

**`PUT /api/v1/preferences/{id}`**

Updates the value of an existing preference.

**Request body:**
```json
{ "value": "light" }
```

**Response:** `200 OK`

---

### Delete Preferences

**`DELETE /api/v1/preferences/{id}`**

Deletes a preference record.

**Response:** `200 OK`

---

## 4. Segment API

### Create a Segment

**`POST /api/v1/segments`**

Creates a new user segment with evaluation criteria.

**Request body:**
```json
{
  "name": "high-value-users",
  "tenantId": "default",
  "criteria": [
    { "field": "country", "operator": "EQUALS", "value": "FR" }
  ]
}
```

**Response:** `201 Created`

---

### Get a Segment

**`GET /api/v1/segments/{id}`**

Retrieves a segment by ID.

**Response:** `200 OK`

---

### Evaluate a Segment

**`POST /api/v1/segments/{id}/evaluate`**

Evaluates whether a profile matches the segment criteria.

**Request body:**
```json
{ "profileId": "550e8400-e29b-41d4-a716-446655440000" }
```

**Response:** `200 OK` — `true` or `false`

---

## Purpose Reference

Standard values for `purpose` in the Consent API:

| Value | Description |
|-------|-------------|
| `MARKETING` | Marketing communications |
| `ANALYTICS` | Usage analytics and statistics |
| `PERSONALIZATION` | Personalized content and recommendations |
| `THIRD_PARTY_SHARING` | Sharing data with third parties |
| `TERMS_AND_CONDITIONS` | Acceptance of terms and conditions |
| `PRIVACY_POLICY` | Acceptance of privacy policy |

---

## Actuator & Health

| Endpoint | Description |
|----------|-------------|
| `GET /actuator/health` | Application health status |
| `GET /actuator/info` | Application version and build info |
| `GET /actuator/metrics` | Prometheus-compatible metrics |
