package es.codeurjc.dad.micro.ejem2.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * API Gateway: punto de entrada único para los clientes. Las rutas están en
 * application.yml; no hace falta escribir código para reenviar peticiones.
 */
@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
}
