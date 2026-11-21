package es.codeurjc.dad.micro.ejem1.catalogo;

import java.math.BigDecimal;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Microservicio de Catálogo: es el DUEÑO de los datos de productos.
 * Nadie más accede a su base de datos; quien necesite un producto usa su API.
 */
@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	CommandLineRunner sampleData(ProductRepository products) {
		return args -> {
			products.save(new Product("Domain-Driven Design", new BigDecimal("54.90"), 10));
			products.save(new Product("Microservices Patterns", new BigDecimal("49.50"), 3));
			products.save(new Product("Building Microservices", new BigDecimal("45.00"), 0));
		};
	}
}
