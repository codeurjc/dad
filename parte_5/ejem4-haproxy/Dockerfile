#################################################
# Imagen base para el contenedor de compilación
#################################################
FROM maven:3.9.11-eclipse-temurin-25 as builder

# Define el directorio de trabajo donde ejecutar comandos
WORKDIR /project

# Copia las dependencias del proyecto
COPY pom.xml /project/

# Descarga las dependencias del proyecto
RUN mvn -B clean verify

# Copia el código del proyecto
COPY /src /project/src

# Compila proyecto
RUN mvn -B -o package -DskipTests

#################################################
# Imagen base para el contenedor de la aplicación
#################################################
FROM eclipse-temurin:25-jre

# Define el directorio de trabajo donde se encuentra el JAR
WORKDIR /usr/app/

# Copia el JAR del contenedor de compilación
COPY --from=builder /project/target/*.jar /usr/app/

# Indica el puerto que expone el contenedor
EXPOSE 8080

# Comando que se ejecuta al hacer docker run
CMD [ "java", "-jar", "ejemplo-haproxy-0.2.0.jar" ]
