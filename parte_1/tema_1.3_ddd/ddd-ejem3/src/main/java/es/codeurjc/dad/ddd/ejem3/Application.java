package es.codeurjc.dad.ddd.ejem3;

import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import es.codeurjc.dad.ddd.ejem3.sales.api.OrderPlacedEvent.Item;
import es.codeurjc.dad.ddd.ejem3.sales.application.SalesService;

/**
 * Monolito modular con dos bounded contexts:
 *
 * <pre>
 *   Ventas (sales) --OrderPlacedEvent--> Logística (shipping) --ACL--> PaqueExpress (legado)
 *     upstream        lenguaje publicado     downstream                   sistema externo
 * </pre>
 *
 * Cada contexto vive en su propio paquete y solo se comunican a través de
 * contratos explícitos (paquete sales.api).
 */
@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	CommandLineRunner demo(SalesService sales) {
		return args -> sales.placeOrder("Ana García", "C/ Tulipán s/n", "Móstoles", "28933",
				List.of(new Item("BOOK-DDD", 2), new Item("MUG-URJC", 1)));
	}
}
