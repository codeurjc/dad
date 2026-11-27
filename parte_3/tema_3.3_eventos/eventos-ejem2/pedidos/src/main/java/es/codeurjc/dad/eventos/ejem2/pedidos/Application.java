package es.codeurjc.dad.eventos.ejem2.pedidos;

import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Servicio de Pedidos: PRODUCTOR de eventos.
 *
 * Publica en el exchange "pedidos" (tipo topic) con claves de enrutado
 * "pedido.confirmado" y "pedido.cancelado". No sabe qué servicios están
 * suscritos ni cuántos hay.
 */
@SpringBootApplication
public class Application {

	public static final String EXCHANGE = "pedidos";

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public TopicExchange pedidosExchange() {
		return new TopicExchange(EXCHANGE);
	}

	@Bean
	public MessageConverter messageConverter() {
		return new JacksonJsonMessageConverter();
	}
}
