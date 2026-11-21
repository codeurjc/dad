package es.codeurjc.dad.eventos.ejem3.pedidos;

import org.springframework.amqp.core.TopicExchange;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class Application {

	public static final String EXCHANGE = "pedidos";

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public TopicExchange pedidosExchange() {
		return new TopicExchange(EXCHANGE);
	}
}
