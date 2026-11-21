package es.codeurjc.dad.obs.ejem3.tienda;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.client.RestClient;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	/**
	 * IMPORTANTE: el RestClient se construye a partir del RestClient.Builder de
	 * Spring Boot. Ese builder ya viene instrumentado: crea un span por cada
	 * llamada y añade la cabecera "traceparent" para que inventario continúe la
	 * misma traza. Con RestClient.builder() a secas, la traza se "rompería".
	 */
	@Bean
	RestClient inventarioClient(RestClient.Builder builder, @Value("${inventario.url}") String url) {
		return builder.baseUrl(url).build();
	}
}
