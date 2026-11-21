package es.codeurjc.dad.obs.ejer1.pedidos;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	/** Construido con el builder de Spring Boot: propaga el contexto de la traza. */
	@Bean
	RestClient pagosClient(RestClient.Builder builder, @Value("${pagos.url}") String url) {
		return builder.baseUrl(url).build();
	}
}
