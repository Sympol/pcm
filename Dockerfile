# ─────────────────────────────────────────────────────────────────────────────
# PCM — Multi-stage Dockerfile
# Stage 1: Build the fat JAR with Maven
# Stage 2: Minimal JRE runtime image
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jdk-jammy AS builder

# Prevent OOM during Maven build and container layer corruption
ENV MAVEN_OPTS="-Xmx1024m -XX:MaxMetaspaceSize=256m"

WORKDIR /build

# Copy Maven wrapper and root POM first (layer cache)
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Copy all module POMs (needed for dependency resolution)
COPY libs/common/pom.xml                                        libs/common/pom.xml
COPY libs/kafka-events/pom.xml                                  libs/kafka-events/pom.xml
COPY libs/grpc-contracts/pom.xml                                libs/grpc-contracts/pom.xml
COPY libs/iab-models/pom.xml                                    libs/iab-models/pom.xml
COPY pcm-domain/pom.xml                                         pcm-domain/pom.xml
COPY pcm-infrastructure-spring/pom.xml                          pcm-infrastructure-spring/pom.xml
COPY profile-context/pom.xml                                    profile-context/pom.xml
COPY profile-context/profile-domain/pom.xml                     profile-context/profile-domain/pom.xml
COPY profile-context/profile-application/pom.xml                profile-context/profile-application/pom.xml
COPY profile-context/profile-infrastructure/pom.xml             profile-context/profile-infrastructure/pom.xml
COPY consent-context/pom.xml                                    consent-context/pom.xml
COPY consent-context/consent-domain/pom.xml                     consent-context/consent-domain/pom.xml
COPY consent-context/consent-application/pom.xml                consent-context/consent-application/pom.xml
COPY consent-context/consent-infrastructure/pom.xml             consent-context/consent-infrastructure/pom.xml
COPY preference-context/pom.xml                                 preference-context/pom.xml
COPY preference-context/preference-domain/pom.xml               preference-context/preference-domain/pom.xml
COPY preference-context/preference-application/pom.xml          preference-context/preference-application/pom.xml
COPY preference-context/preference-infrastructure/pom.xml       preference-context/preference-infrastructure/pom.xml
COPY segment-context/pom.xml                                    segment-context/pom.xml
COPY segment-context/segment-domain/pom.xml                     segment-context/segment-domain/pom.xml
COPY segment-context/segment-application/pom.xml                segment-context/segment-application/pom.xml
COPY segment-context/segment-infrastructure/pom.xml             segment-context/segment-infrastructure/pom.xml

# Download dependencies (cached layer — only re-runs when POMs change)
# Add retry mechanism to be robust against transient Maven Central network drops
RUN ./mvnw dependency:go-offline -B -q --no-transfer-progress -pl pcm-infrastructure-spring -am || \
    ./mvnw dependency:go-offline -B -q --no-transfer-progress -pl pcm-infrastructure-spring -am

# Copy all source code
COPY libs/common/src                                            libs/common/src
COPY libs/kafka-events/src                                      libs/kafka-events/src
COPY libs/grpc-contracts/src                                    libs/grpc-contracts/src
COPY libs/iab-models/src                                        libs/iab-models/src
COPY pcm-domain/src                                             pcm-domain/src
COPY pcm-infrastructure-spring/src                              pcm-infrastructure-spring/src
COPY profile-context/profile-domain/src                         profile-context/profile-domain/src
COPY profile-context/profile-application/src                    profile-context/profile-application/src
COPY profile-context/profile-infrastructure/src                 profile-context/profile-infrastructure/src
COPY consent-context/consent-domain/src                         consent-context/consent-domain/src
COPY consent-context/consent-application/src                    consent-context/consent-application/src
COPY consent-context/consent-infrastructure/src                 consent-context/consent-infrastructure/src
COPY preference-context/preference-domain/src                   preference-context/preference-domain/src
COPY preference-context/preference-application/src              preference-context/preference-application/src
COPY preference-context/preference-infrastructure/src           preference-context/preference-infrastructure/src
COPY segment-context/segment-domain/src                         segment-context/segment-domain/src
COPY segment-context/segment-application/src                    segment-context/segment-application/src
COPY segment-context/segment-infrastructure/src                 segment-context/segment-infrastructure/src

# Build — skip tests (run separately in CI)
RUN ./mvnw package -pl pcm-infrastructure-spring -am -DskipTests -q

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine AS runtime

# Security: run as non-root user
RUN addgroup -S pcm && adduser -S pcm -G pcm

WORKDIR /app

# Copy the fat JAR from builder
COPY --from=builder /build/pcm-infrastructure-spring/target/pcm-infrastructure-spring-*.jar app.jar

# Ensure the non-root user owns the app
RUN chown pcm:pcm app.jar

USER pcm

# Expose HTTP port
EXPOSE 8080

# Health check via Spring Boot Actuator
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

# JVM tuning: container-aware heap, G1GC, structured logging
ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-XX:+UseG1GC", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-Dorg.apache.kafka.sasl.oauthbearer.allowed.urls=", \
  "-jar", "app.jar"]
