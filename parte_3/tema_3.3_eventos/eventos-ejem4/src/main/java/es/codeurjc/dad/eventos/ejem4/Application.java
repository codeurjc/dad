package es.codeurjc.dad.eventos.ejem4;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import es.codeurjc.dad.eventos.ejem4.application.AccountCommandService;
import es.codeurjc.dad.eventos.ejem4.eventstore.EventStore;
import es.codeurjc.dad.eventos.ejem4.eventstore.InMemoryEventStore;
import es.codeurjc.dad.eventos.ejem4.query.AccountProjections;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public AccountProjections accountProjections() {
		return new AccountProjections();
	}

	@Bean
	public EventStore eventStore(AccountProjections projections) {
		EventStore store = new InMemoryEventStore();
		store.subscribe(projections::on);
		return store;
	}

	@Bean
	public AccountCommandService accountCommandService(EventStore store) {
		return new AccountCommandService(store);
	}
}
