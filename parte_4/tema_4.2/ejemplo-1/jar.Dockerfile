# Selecciona la imagen base
FROM eclipse-temurin:25-jre

# Define el directorio de trabajo para el comando
WORKDIR /usr/src/app/

# Copia de la aplicación compilada
COPY target/*.jar /usr/src/app/

# Indica el puerto que expone el contenedor
EXPOSE 8080

# Comando que se ejecuta al hacer docker run
CMD [ "java", "-jar", "java-webapp-0.0.1.jar" ]