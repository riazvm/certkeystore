# Build stage
FROM eclipse-temurin:17-jdk AS build
WORKDIR /app

# Copy maven wrapper and pom.xml
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Make the mvnw script executable
RUN chmod +x mvnw

# Download dependencies (this layer will be cached unless pom.xml changes)
RUN ./mvnw dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN ./mvnw package -DskipTests
RUN mkdir -p target/dependency && (cd target/dependency; jar -xf ../*.jar)

# Runtime stage
FROM eclipse-temurin:17-jre
VOLUME /tmp
VOLUME /mnt/certs

# ARGs for dynamic app name identification
ARG DEPENDENCY=/app/target/dependency

# Copy application from build stage
COPY --from=build ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY --from=build ${DEPENDENCY}/META-INF /app/META-INF
COPY --from=build ${DEPENDENCY}/BOOT-INF/classes /app

# Create directory for certificates
RUN mkdir -p /mnt/certs && chmod 755 /mnt/certs

# Expose HTTPS port
EXPOSE 8443

# Set entry point
ENTRYPOINT ["java", \
           "-cp", "app:app/lib/*", \
           "-Dspring.profiles.active=${SPRING_PROFILES_ACTIVE:-default}", \
           "com.riaz.certkeystore.CertManagerDemoApplication"]