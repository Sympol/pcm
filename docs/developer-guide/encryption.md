# Developer Guide: PII Encryption

This guide explains how to work with PCM's encryption subsystem as a developer. It
covers using `IEncryptionService` in the domain layer, annotating PII fields,
configuring the Spring Boot integration, and writing tests that work with encryption.

---

## 1. Core Principle: Encryption is Transparent

The domain layer **never** calls encryption APIs directly. Encryption and decryption
happen automatically in the infrastructure layer via JPA entity listeners. Domain
objects always work with plaintext values.

```
Domain layer          Infrastructure layer         Database
─────────────         ────────────────────         ────────
Profile(handle)  →→→  @PrePersist: encrypt  →→→   ciphertext
Profile(handle)  ←←←  @PostLoad:   decrypt  ←←←   ciphertext
```

If you are writing domain logic, you do not need to import anything from the
encryption package. If you are writing infrastructure code (new entities, new
repositories), read §2 and §3.

---

## 2. Annotating PII Fields

Mark any JPA entity field that contains PII with `@EncryptedField`:

```java
import dev.vibeafrika.pcm.domain.encryption.EncryptedField;
import dev.vibeafrika.pcm.domain.encryption.PIIType;

@Entity
@EntityListeners({AuditingEntityListener.class, ProfileEncryptionEntityListener.class})
public class ProfileJpaEntity {

    // Non-PII field — stored as plaintext, fully searchable
    @Column(name = "tenant_id")
    private String tenantId;

    // PII field — encrypted at rest, searchable via blind index
    @EncryptedField(piiType = PIIType.STANDARD_PII, searchable = true, blindIndexField = "handleBlindIndex")
    @Column(name = "handle", length = 500)
    private String handle;

    // Blind index column — populated automatically, used for exact-match search
    @Column(name = "handle_blind_index")
    private String handleBlindIndex;
}
```

### `@EncryptedField` attributes

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `piiType` | `PIIType` | Yes | Classification: `STANDARD_PII`, `SENSITIVE_PII`, `QUASI_IDENTIFIER` |
| `searchable` | `boolean` | No (default `false`) | Whether to generate a blind index for this field |
| `blindIndexField` | `String` | If `searchable = true` | Name of the field that stores the blind index |

### PII types

| `PIIType` | Examples |
|-----------|----------|
| `STANDARD_PII` | Email, phone, name, handle |
| `SENSITIVE_PII` | Health data, biometric data |
| `QUASI_IDENTIFIER` | IP address, user agent |

### Adding a blind index column

For every `searchable = true` field, add a corresponding column to the entity and a
database index:

```java
// In the entity
@Column(name = "email_blind_index")
private String emailBlindIndex;
```

```sql
-- In the migration
CREATE INDEX idx_consent_email_blind ON consent_records(email_blind_index);
```

Search by blind index, not by the encrypted column:

```java
// In the repository
Optional<ConsentJpaEntity> findByEmailBlindIndex(String blindIndex);
```

To generate the blind index value for a query parameter, call:

```java
Result<BlindIndex, EncryptionError> idx = encryptionService.generateBlindIndex(email, recordSalt);
```

---

## 3. Wiring the Entity Listener

Each bounded context has its own entity listener class. The listener uses a static
delegate pattern so that the Spring-managed `DatabaseEncryptionAdapter` can be
injected without creating circular dependencies.

The delegates are set automatically by `DatabaseEncryptionAdapterConfiguration` at
startup. You only need to:

1. Create the listener class (copy the pattern from `ProfileEncryptionEntityListener`).
2. Add `@EntityListeners({..., YourContextEncryptionEntityListener.class})` to the
   entity.
3. Register the listener in `DatabaseEncryptionAdapterConfiguration`.

```java
// Example listener (copy for each new bounded context)
public class MyContextEncryptionEntityListener {

    private static Consumer<Object> encryptDelegate;
    private static Consumer<Object> decryptDelegate;

    public static void setDelegates(Consumer<Object> encrypt, Consumer<Object> decrypt) {
        encryptDelegate = encrypt;
        decryptDelegate = decrypt;
    }

    @PrePersist
    @PreUpdate
    public void onWrite(Object entity) {
        if (encryptDelegate != null) encryptDelegate.accept(entity);
    }

    @PostLoad
    public void onRead(Object entity) {
        if (decryptDelegate != null) decryptDelegate.accept(entity);
    }
}
```

---

## 4. Using `IEncryptionService` Directly

Most code should not call `IEncryptionService` directly — the entity listener handles
it. The cases where you might call it directly are:

- Generating a blind index for a search query parameter.
- Cross-context data sharing (re-encrypting data from one context to another).
- Batch operations where you control the encryption lifecycle explicitly.

```java
@Service
public class ProfileSearchService {

    private final IEncryptionService encryptionService;

    public ProfileSearchService(IEncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    public Optional<Profile> findByHandle(String handle, String recordSalt) {
        // Generate blind index for the search value
        Result<BlindIndex, EncryptionError> result =
            encryptionService.generateBlindIndex(handle, recordSalt);

        if (result.isFailure()) {
            throw new RuntimeException("Failed to generate blind index: " + result.getError());
        }

        return profileRepository.findByHandleBlindIndex(result.getValue().getValue());
    }
}
```

### Cross-context data sharing

```java
// Re-encrypt data from Profile context to Consent context
Result<Ciphertext, EncryptionError> reEncrypted = encryptionService.shareAcrossContexts(
    sourceCiphertext,
    BoundedContext.PROFILE,
    BoundedContext.CONSENT
);
```

### Batch operations

```java
// Encrypt a list of values in one call (more efficient than individual calls)
Result<List<Ciphertext>, EncryptionError> batch =
    encryptionService.encryptBatch(List.of(email1, email2, email3), BoundedContext.CONSENT);
```

---

## 5. Configuration Reference

All encryption settings live under the `pcm.encryption` prefix in `application.yml`.

```yaml
pcm:
  encryption:
    # Environment identifier — must match DEV, STAGING, or PROD
    environment: PROD

    # Default bounded context for operations that don't specify one
    default-context: PROFILE

    # Secret global salt for blind index generation (keep secret, rotate with DEKs)
    blind-index-global-salt: ${BLIND_INDEX_GLOBAL_SALT}

    kms:
      # KMS provider: AWS_KMS, AZURE_KEY_VAULT, GCP_KMS, VAULT, HSM
      provider: AWS_KMS
      endpoint: https://kms.us-east-1.amazonaws.com
      region: us-east-1
      # FIPS_140_2_L2 for non-prod, FIPS_140_2_L3 for prod
      certification: FIPS_140_2_L3
      health-check-interval: 30s

      mtls:
        enabled: true
        keystore-path: /etc/pcm/certs/client.p12
        keystore-password: ${KMS_KEYSTORE_PASSWORD}
        truststore-path: /etc/pcm/certs/truststore.p12
        truststore-password: ${KMS_TRUSTSTORE_PASSWORD}

      failover:
        enabled: true
        provider: AWS_KMS
        endpoint: https://kms.eu-west-1.amazonaws.com
        region: eu-west-1

    dek-cache:
      max-size: 1000      # LRU eviction above this limit
      ttl-minutes: 60     # DEKs evicted after 1 hour
      secure-memory: true # Wipe key material on eviction

    key-rotation:
      dek-rotation-days: 90
      dek-rotation-bytes: 1099511627776   # 1 TB
      dek-rotation-operations: 4294967296 # 2^32
      kek-rotation-days: 365
      emergency-rotation-time-minutes: 15

    audit:
      level: HIGH          # CRITICAL, HIGH, MEDIUM, LOW
      retain-days: 365     # 1 year minimum; use 2555 (7 years) for compliance-critical
      encrypt-logs: true
      sign-logs: true
      sampling-rate: 1     # 1 = log every operation; 10 = log 1 in 10

    network:
      mtls-enabled: true
      private-subnet-only: true
      allowed-service-ips:
        - 10.0.1.0/24
      circuit-breaker:
        failure-threshold: 5
        recovery-time-seconds: 60
        half-open-max-calls: 3
```

### Minimal test configuration

```yaml
# application-test.yml
pcm:
  encryption:
    environment: DEV
    default-context: PROFILE
    blind-index-global-salt: test-global-salt-for-unit-tests-only
    kms:
      provider:       # leave blank — tests provide a mock KMS bean
      region: us-east-1
      certification: FIPS_140_2_L2
    dek-cache:
      max-size: 100
      ttl-minutes: 60
    key-rotation:
      dek-rotation-days: 90
      kek-rotation-days: 365
      emergency-rotation-time-minutes: 15
    audit:
      level: HIGH
      retain-days: 365
      encrypt-logs: true
      sign-logs: true
    network:
      mtls-enabled: false
      private-subnet-only: false
```

---

## 6. Testing with Encryption

### Unit tests (domain layer)

Domain layer unit tests do not need encryption infrastructure. The domain layer works
with plaintext values — no mocking required.

```java
@Test
void profileHandleIsStoredAsProvided() {
    Profile profile = Profile.create(tenantId, "alice");
    assertThat(profile.getHandle()).isEqualTo("alice");
    // No encryption involved — domain layer is unaware of it
}
```

### Integration tests (infrastructure layer)

Integration tests that exercise the full persistence stack need a real or mock
`IEncryptionService`. PCM provides a test configuration that wires a mock KMS:

```java
@SpringBootTest
@ActiveProfiles("test")
class ProfileEncryptionIntegrationTest {

    @Autowired
    private ProfileRepository profileRepository;

    @Test
    void handleIsEncryptedInDatabase() {
        Profile profile = profileRepository.save(new Profile("alice"));

        // Query the raw JDBC value — should be ciphertext, not plaintext
        String raw = jdbcTemplate.queryForObject(
            "SELECT handle FROM profile_profiles WHERE id = ?",
            String.class, profile.getId()
        );

        assertThat(raw).isNotEqualTo("alice");
        assertThat(raw).startsWith("\\x01"); // version byte 0x01
    }

    @Test
    void handleIsDecryptedOnLoad() {
        Profile saved = profileRepository.save(new Profile("alice"));
        Profile loaded = profileRepository.findById(saved.getId()).orElseThrow();

        assertThat(loaded.getHandle()).isEqualTo("alice");
    }
}
```

### Testing blind index search

```java
@Test
void findByHandleUsesBlindIndex() {
    profileRepository.save(new Profile("alice"));

    // Search using the blind index — not the encrypted column
    Optional<Profile> found = profileRepository.findByHandle("alice");

    assertThat(found).isPresent();
    assertThat(found.get().getHandle()).isEqualTo("alice");
}
```

### Property-based tests

PCM uses [jqwik](https://jqwik.net/) for property-based testing. Key properties to
validate in new code:

```java
@Property
void encryptDecryptRoundTrip(@ForAll @StringLength(min = 1, max = 1000) String plaintext) {
    Result<Ciphertext, EncryptionError> encrypted =
        encryptionService.encrypt(plaintext, BoundedContext.PROFILE);
    assertThat(encrypted.isSuccess()).isTrue();

    Result<String, DecryptionError> decrypted =
        encryptionService.decrypt(encrypted.getValue(), BoundedContext.PROFILE);
    assertThat(decrypted.isSuccess()).isTrue();
    assertThat(decrypted.getValue()).isEqualTo(plaintext);
}
```

---

## 7. Common Mistakes

**Storing plaintext in an encrypted column**
If you populate an encrypted column without going through the entity listener (e.g.,
via a native SQL migration), the value will be stored as plaintext. On the next read,
decryption will fail with `INVALID_CIPHERTEXT_FORMAT`. Always use JPA to write to
encrypted columns.

**Searching by the encrypted column directly**
Encrypted values are not deterministic — the same plaintext produces different
ciphertexts each time. Searching by the encrypted column will never return results.
Always search by the blind index column.

**Using the test global salt in production**
The `test-global-salt-for-unit-tests-only` value in `application-test.yml` is public.
Using it in production makes blind indexes predictable. Always set
`pcm.encryption.blind-index-global-salt` from a secret (e.g., environment variable
or secrets manager).

**Logging plaintext PII**
The audit logger deliberately excludes plaintext PII. Do not add plaintext PII to
application logs, exception messages, or metrics labels.
