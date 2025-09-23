FROM gradle:8.7.0-jdk21-alpine AS builder

WORKDIR /app
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
COPY src ./src

RUN gradle clean bootJar -x test

FROM eclipse-temurin:21-jre-alpine

RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

WORKDIR /app

COPY --from=builder /app/build/libs/*.jar app.jar

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD nc -z localhost 8080 && nc -z localhost 9090 || exit 1

USER appuser

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]