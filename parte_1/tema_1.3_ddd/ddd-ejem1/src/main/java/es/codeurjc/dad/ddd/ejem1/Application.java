package es.codeurjc.dad.ddd.ejem1;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import es.codeurjc.dad.ddd.ejem1.domain.Address;
import es.codeurjc.dad.ddd.ejem1.domain.Customer;
import es.codeurjc.dad.ddd.ejem1.domain.CustomerId;
import es.codeurjc.dad.ddd.ejem1.domain.EmailAddress;
import es.codeurjc.dad.ddd.ejem1.domain.Money;

@SpringBootApplication
public class Application {

	private static final Logger log = LoggerFactory.getLogger(Application.class);

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	CommandLineRunner demo() {
		return args -> {
			// Value Objects: se comparan por valor
			Money a = Money.euros("10");
			Money b = Money.euros("10.00");
			log.info("¿{} es igual a {}? {}", a, b, a.equals(b));
			log.info("{} + {} = {}", a, b, a.plus(b));

			// Entidades: se comparan por identidad
			CustomerId id = CustomerId.newId();
			Address madrid = new Address("C/ Tulipán s/n", "Móstoles", "28933", "España");
			Customer ana = new Customer(id, "Ana", new EmailAddress("Ana@URJC.es"), madrid);
			Customer anaTrasCambios = new Customer(id, "Ana García", new EmailAddress("ana@gmail.com"), madrid);
			log.info("¿Es la misma clienta aunque cambien sus datos? {}", ana.equals(anaTrasCambios));

			ana.registerPurchase(Money.euros("750"));
			ana.registerPurchase(Money.euros("300"));
			log.info("{}", ana);

			try {
				new EmailAddress("esto-no-es-un-email");
			} catch (IllegalArgumentException e) {
				log.info("Un Value Object no puede ser inválido: {}", e.getMessage());
			}
		};
	}
}
