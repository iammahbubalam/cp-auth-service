# Dockerfile
# Stage args allow easy pinning/upgrades
ARG GRADLE_IMAGE=gradle:9.1.0-jdk21
ARG RUNTIME_IMAGE=eclipse-temurin:21-jre

FROM ${GRADLE_IMAGE} AS builder
WORKDIR /app

# Copy gradle wrapper and build files first to leverage cache
COPY build.gradle settings.gradle gradle.properties* gradlew ./
COPY gradle ./gradle

# Ensure wrapper is executable and download dependencies (if wrapper exists)
RUN if [ -f ./gradlew ]; then chmod +x ./gradlew && ./gradlew --no-daemon --version; fi

# Copy source and build the fat jar (Spring Boot)
COPY src ./src
RUN if [ -f ./gradlew ]; then ./gradlew clean bootJar -x test --no-daemon; else gradle clean bootJar -x test; fi

# Final runtime image (glibc-based for best compatibility)
FROM ${RUNTIME_IMAGE} AS runtime

# create non-root user
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 appuser

WORKDIR /app

# Copy the jar from builder (use explicit path or ARG if needed)
COPY --from=builder --chown=appuser:appgroup /app/build/libs/*.jar /app/app.jar

# Install curl for healthcheck and then clean apt lists (Debian-based Temurin)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 8080

# Simple healthcheck hitting actuator; replace path if needed
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

USER appuser

# JVM flags tuned for container environments; adjust memory flags as needed
ENTRYPOINT ["java","-XX:+UseContainerSupport","-XX:MaxRAMPercentage=75.0","-Djava.security.egd=file:/dev/./urandom","-jar","/app/app.jar"]
