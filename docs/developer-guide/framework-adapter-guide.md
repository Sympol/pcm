# Adding a New Framework Adapter to PCM

This guide walks through implementing a new infrastructure adapter for PCM. The modular monolith architecture means all four bounded contexts (Preference, Profile, Consent, Segment) must be wired into a single deployable application — but the domain and application layers are completely framework-agnostic, so you only need to implement the infrastructure layer.

PCM ships with a **Spring Boot** adapter (`pcm-infrastructure-spring`). This guide uses it as the reference implementation and shows the equivalent for **Quarkus**.

## Prerequisites

Before starting, understand the three-layer module structure each bounded context follows:

```
{context}-domain/        ← Pure Java, zero framework deps (pure-assert only)
{context}-application/   ← Pure Java, depends only on domain
{context}-infrastructure/ ← Framework-specific, depends on domain + application
```

Your new adapter lives entirely in the infrastructure layer and a new top-level application module (e.g., `pcm-infrastructure-quarkus`).

---

## Step 1: Create the Infrastructure Module

Create a new Maven module for your framework. Use the Spring Boot module as a reference:

```
pcm-infrastructure-{framework}/
├── pom.xml
└── src/main/java/dev/vibeafrika/pcm/infrastructure/{framework}/
    ├── web/          ← REST controllers / JAX-RS resources
    ├── config/       ← DI configuration, transaction config
    ├── event/        ← Event bus implementation
    └── Application.java
```

Your `pom.xml` must declare dependencies on all four context infrastructure modules:

```xml
<dependencies>
    <!-- All bounded context infrastructure modules -->
    <dependency>
        <groupId>dev.vibeafrika.pcm</groupId>
        <artifactId>preference-infrastructure</artifactId>
    </dependency>
    <dependency>
        <groupId>dev.vibeafrika.pcm</groupId>
        <artifactId>profile-infrastructure</artifactId>
    </dependency>
    <dependency>
        <groupId>dev.vibeafrika.pcm</groupId>
        <artifactId>consent-infrastructure</artifactId>
    </dependency>
    <dependency>
        <groupId>dev.vibeafrika.pcm</groupId>
        <artifactId>segment-infrastructure</artifactId>
    </dependency>

    <!-- Your framework -->
    <dependency>
        <groupId>io.quarkus</groupId>
        <artifactId>quarkus-resteasy-reactive</artifactId>
    </dependency>
    <!-- ... other framework deps -->
</dependencies>
```

---

## Step 2: Implement All Repository Interfaces

Each bounded context defines a repository interface (port) in its domain module. You must provide a concrete implementation for each one.

### 2.1 Preference Context

**Interface:** `dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository`

```java
public interface PreferenceRepository {
    Preference save(Preference preference);
    Optional<Preference> findById(PreferenceId id);
    Optional<Preference> findByKey(PreferenceKey key);
    Optional<Preference> findByProfileId(ProfileId profileId);
    Optional<Preference> findByProfileIdAndTenant(ProfileId profileId, TenantId tenantId);
    void delete(Preference preference);
}
```

### 2.2 Profile Context

**Interface:** `dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository`

```java
public interface ProfileRepository {
    Profile save(Profile profile);
    Optional<Profile> findById(ProfileId id);
    Optional<Profile> findByHandle(Handle handle, TenantId tenantId);
    Optional<Profile> findByIdAndTenant(ProfileId id, TenantId tenantId);
    boolean existsByHandle(Handle handle, TenantId tenantId);
    void delete(Profile profile);
}
```

### 2.3 Consent Context

**Interface:** `dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository`

```java
public interface ConsentRepository {
    Consent save(Consent consent);
    Optional<Consent> findById(ConsentId id);
    List<Consent> findByProfile(ProfileId profileId);
    List<Consent> findActiveConsents(ProfileId profileId);
    List<Consent> findByPurpose(ConsentPurpose purpose);
    List<Consent> getConsentHistory(ProfileId profileId);
    void delete(Consent consent);
}
```

### 2.4 Segment Context

**Interface:** `dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository`

```java
public interface SegmentRepository {
    Segment save(Segment segment);
    Optional<Segment> findById(SegmentId id);
    Optional<Segment> findByName(SegmentName name, TenantId tenantId);
    List<Segment> findByTenant(TenantId tenantId);
    List<Segment> findByProfile(ProfileId profileId, TenantId tenantId);
    boolean existsByName(SegmentName name, TenantId tenantId);
    void delete(Segment segment);
    List<Segment> findMatchingSegments(ProfileId profileId, TenantId tenantId);
}
```

---

## Step 3: Create Persistence Entities and Mappers

Each bounded context needs its own persistence entity class and a mapper. The mapper translates between the domain entity and the persistence entity — this is where all framework-specific annotations live.

### Table Naming Convention

All tables use a bounded context prefix to avoid collisions in the shared database:

| Context    | Table prefix   | Example                    |
|------------|----------------|----------------------------|
| Preference | `preference_`  | `preference_preferences`   |
| Profile    | `profile_`     | `profile_profiles`         |
| Consent    | `consent_`     | `consent_consents`         |
| Segment    | `segment_`     | `segment_segments`         |

### Mapper Pattern

Every mapper follows the same two-method pattern. Here is the Preference mapper as a reference:

```java
public class PreferenceMapper {

    // Domain → Persistence: unwrap value objects to primitives
    public static PreferenceJpaEntity toJpaEntity(Preference preference) {
        PreferenceJpaEntity entity = new PreferenceJpaEntity();
        entity.setId(preference.getId().getValue());           // PreferenceId → UUID
        entity.setTenantId(preference.getTenantId().getValue()); // TenantId → String
        entity.setProfileId(preference.getProfileId().getValue()); // ProfileId → UUID
        entity.setSettings(preference.getSettings());
        entity.setLastUpdated(preference.getLastUpdated());
        entity.setDeleted(preference.isDeleted());
        return entity;
    }

    // Persistence → Domain: use the reconstitute() factory method
    public static Preference toDomainEntity(PreferenceJpaEntity entity) {
        return Preference.reconstitute(
            PreferenceId.of(entity.getId()),
            TenantId.of(entity.getTenantId()),
            ProfileId.of(entity.getProfileId()),
            entity.getSettings(),
            entity.getLastUpdated(),
            entity.isDeleted()
        );
    }
}
```

Key rules:
- **Never call `new DomainEntity()`** from the mapper — always use the `reconstitute()` factory method. This bypasses business invariant checks that only apply to new entity creation.
- **Unwrap value objects** (`getId().getValue()`) when writing to persistence.
- **Wrap primitives** back into value objects (`ProfileId.of(entity.getId())`) when reading from persistence.
- The mapper is a plain static utility class — no framework annotations.

---

## Step 4: Configure Dependency Injection

Use cases receive all dependencies through constructor injection. Your framework's DI container must wire them up. No `@Autowired` or `@Inject` annotations appear in the use case classes themselves.

### Spring Boot reference (PreferenceUseCaseConfiguration)

```java
@Configuration
public class PreferenceUseCaseConfiguration {

    @Bean
    public CreatePreferenceUseCase createPreferenceUseCase(
            PreferenceRepository preferenceRepository,
            EventPublisher eventPublisher) {
        return new CreatePreferenceUseCase(preferenceRepository, eventPublisher);
    }

    @Bean
    public GetPreferenceUseCase getPreferenceUseCase(
            PreferenceRepository preferenceRepository) {
        return new GetPreferenceUseCase(preferenceRepository);
    }

    // ... repeat for UpdatePreferenceUseCase, DeletePreferenceUseCase
}
```

### Quarkus equivalent

```java
@ApplicationScoped
public class PreferenceUseCaseProducer {

    @Inject
    PreferenceRepository preferenceRepository;

    @Inject
    EventPublisher eventPublisher;

    @Produces
    @ApplicationScoped
    public CreatePreferenceUseCase createPreferenceUseCase() {
        return new CreatePreferenceUseCase(preferenceRepository, eventPublisher);
    }

    @Produces
    @ApplicationScoped
    public GetPreferenceUseCase getPreferenceUseCase() {
        return new GetPreferenceUseCase(preferenceRepository);
    }
}
```

You need one configuration class per bounded context (Preference, Profile, Consent, Segment).

---

## Step 5: Configure Transaction Management

Use cases define transaction boundaries by method scope — they contain no `@Transactional` annotations. Your adapter must apply transactions externally.

### Spring Boot reference (TransactionConfiguration)

Spring Boot uses `TransactionInterceptor` + `BeanNameAutoProxyCreator` to wrap use case beans:

```java
@Configuration
public class TransactionConfiguration {

    @Bean("pcmTransactionInterceptor")
    public TransactionInterceptor transactionInterceptor(PlatformTransactionManager txManager) {
        TransactionInterceptor interceptor = new TransactionInterceptor();
        interceptor.setTransactionManager(txManager);

        Properties attrs = new Properties();
        // Write operations: REQUIRED, rollback on any exception
        attrs.setProperty("execute*", "PROPAGATION_REQUIRED,-Exception");
        attrs.setProperty("save*",    "PROPAGATION_REQUIRED,-Exception");
        attrs.setProperty("delete*",  "PROPAGATION_REQUIRED,-Exception");
        // Read operations: read-only
        attrs.setProperty("get*",     "PROPAGATION_REQUIRED,readOnly");
        attrs.setProperty("find*",    "PROPAGATION_REQUIRED,readOnly");
        attrs.setProperty("verify*",  "PROPAGATION_REQUIRED,readOnly");

        interceptor.setTransactionAttributes(attrs);
        return interceptor;
    }

    @Bean
    public BeanNameAutoProxyCreator transactionAutoProxy() {
        BeanNameAutoProxyCreator creator = new BeanNameAutoProxyCreator();
        creator.setProxyTargetClass(true);
        creator.setBeanNames("*UseCase");
        creator.setInterceptorNames("pcmTransactionInterceptor");
        return creator;
    }
}
```

### Quarkus equivalent

With Quarkus, wrap the use case producer methods with `@Transactional`:

```java
@ApplicationScoped
public class PreferenceUseCaseProducer {

    @Produces
    @ApplicationScoped
    @Transactional  // Quarkus applies transaction to the produced bean's methods
    public CreatePreferenceUseCase createPreferenceUseCase() {
        return new CreatePreferenceUseCase(preferenceRepository, eventPublisher);
    }
}
```

Or use a CDI interceptor binding to apply transactions by method name pattern.

---

## Step 6: Implement the Event Bus

The `EventPublisher` interface (defined in `preference-application`) must be implemented using your framework's event mechanism.

**Interface:**
```java
public interface EventPublisher {
    <T> void publish(T event);
}
```

### Spring Boot reference

```java
@Component
public class SpringEventPublisher implements EventPublisher {

    private final ApplicationEventPublisher publisher;

    public SpringEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public <T> void publish(T event) {
        publisher.publishEvent(event);
    }
}
```

### Quarkus equivalent

```java
@ApplicationScoped
public class QuarkusEventPublisher implements EventPublisher {

    @Inject
    Event<Object> cdiEvent;

    @Override
    public <T> void publish(T event) {
        cdiEvent.fire(event);
    }
}
```

---

## Step 7: Create REST Controllers / Resources

Controllers delegate directly to use cases. No business logic belongs here.

### Spring Boot reference

```java
@RestController
@RequestMapping("/api/v1/preferences")
public class PreferenceController {

    private final CreatePreferenceUseCase createUseCase;
    private final GetPreferenceUseCase getUseCase;

    public PreferenceController(CreatePreferenceUseCase createUseCase,
                                GetPreferenceUseCase getUseCase) {
        this.createUseCase = createUseCase;
        this.getUseCase = getUseCase;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PreferenceResponse create(@RequestBody CreatePreferenceRequest request) {
        return createUseCase.execute(request);
    }

    @GetMapping("/{id}")
    public PreferenceResponse get(@PathVariable UUID id) {
        return getUseCase.execute(new GetPreferenceRequest(id));
    }
}
```

### Quarkus equivalent

```java
@Path("/api/v1/preferences")
@ApplicationScoped
public class PreferenceResource {

    @Inject
    CreatePreferenceUseCase createUseCase;

    @Inject
    GetPreferenceUseCase getUseCase;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response create(CreatePreferenceRequest request) {
        PreferenceResponse response = createUseCase.execute(request);
        return Response.status(Response.Status.CREATED).entity(response).build();
    }

    @GET
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public PreferenceResponse get(@PathParam("id") UUID id) {
        return getUseCase.execute(new GetPreferenceRequest(id));
    }
}
```

---

## Step 8: Map Domain Exceptions to HTTP Responses

Domain exceptions must be translated to HTTP responses at the infrastructure boundary. The domain layer throws typed exceptions; the adapter maps them to status codes.

| Domain Exception              | HTTP Status |
|-------------------------------|-------------|
| `PreferenceNotFoundException` | 404         |
| `ProfileNotFoundException`    | 404         |
| `ConsentNotFoundException`    | 404         |
| `SegmentNotFoundException`    | 404         |
| `ProfileDeletedException`     | 410         |
| `InvalidHandleException`      | 400         |
| `StringTooShortException`     | 400         |
| `InvalidPatternException`     | 400         |
| `ConsentRevokedException`     | 409         |
| `InvalidConsentPurposeException` | 400      |

All error responses must follow [RFC 7807 Problem Details](https://datatracker.ietf.org/doc/html/rfc7807) with `Content-Type: application/problem+json`.

### Spring Boot reference

```java
@RestControllerAdvice
public class ProblemDetailExceptionHandler {

    @ExceptionHandler(PreferenceNotFoundException.class)
    public ProblemDetail handleNotFound(PreferenceNotFoundException ex,
                                        HttpServletRequest request) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND, ex.getMessage());
        problem.setType(URI.create("https://pcm.vibeafrika.dev/errors/not-found"));
        problem.setTitle("Resource Not Found");
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }
}
```

### Quarkus equivalent

```java
@Provider
public class PreferenceNotFoundExceptionMapper
        implements ExceptionMapper<PreferenceNotFoundException> {

    @Override
    public Response toResponse(PreferenceNotFoundException ex) {
        Map<String, Object> problem = Map.of(
            "type",      "https://pcm.vibeafrika.dev/errors/not-found",
            "title",     "Resource Not Found",
            "status",    404,
            "detail",    ex.getMessage(),
            "timestamp", Instant.now().toString()
        );
        return Response.status(404)
            .type("application/problem+json")
            .entity(problem)
            .build();
    }
}
```
