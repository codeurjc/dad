# Dockerfile for Spring Boot application

# Build stage
FROM maven:3-eclipse-temurin-25 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests

# Run stage
FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build /app/target/ejem0-employee-0.0.1-SNAPSHOT.jar .
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "ejem0-employee-0.0.1-SNAPSHOT.jar"]
