FROM maven:3.9.11-eclipse-temurin-25 as builder
COPY . /src
WORKDIR /src
RUN mvn package -DskipTests

FROM eclipse-temurin:25-jre
COPY --from=builder /src/target/ejem4b-haproxy-0.1.0.jar /
CMD ["java", "-jar", "ejem4b-haproxy-0.1.0.jar"] 