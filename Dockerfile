# Multi-stage build for Spring Boot backend
FROM maven:3.9-eclipse-temurin-17-alpine AS build

WORKDIR /app

# Copy all source code
COPY pom.xml .
COPY src ./src

# Build the application (skip tests for faster builds)
RUN mvn clean package -DskipTests -Dmaven.test.skip=true

# Runtime stage
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Create non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy jar from build stage
COPY --from=build /app/target/*.jar app.jar

# Create directory for certificates (will be mounted as volume)
RUN mkdir -p /app/certs && chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/pass/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
