package es.codeurjc.dad.micro.ejer1.libros;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	CommandLineRunner sampleData(BookRepository books) {
		return args -> {
			books.save(new Book("978-0321125217", "Domain-Driven Design", "Eric Evans", 2));
			books.save(new Book("978-1617294549", "Microservices Patterns", "Chris Richardson", 1));
			books.save(new Book("978-1680502398", "Release It!", "Michael Nygard", 3));
		};
	}
}
