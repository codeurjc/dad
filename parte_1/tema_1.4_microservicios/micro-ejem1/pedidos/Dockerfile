#################################################
# Contenedor de compilación
#################################################
FROM maven:3.9.11-eclipse-temurin-25 AS builder
WORKDIR /project

# Primero solo el pom: las dependencias quedan en una capa cacheada
COPY pom.xml /project/
RUN mvn -B dependency:go-offline

COPY src /project/src
RUN mvn -B package -DskipTests

#################################################
# Contenedor de la aplicación
#################################################
FROM eclipse-temurin:25-jre
WORKDIR /usr/app/
COPY --from=builder /project/target/*.jar /usr/app/app.jar
EXPOSE 8082
CMD [ "java", "-jar", "app.jar" ]
