package es.codeurjc.dad.eventos.ejer1.pagos;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Application {

	public static final String EXCHANGE = "tienda";
	public static final String Q_STOCK_RESERVED = "pagos.stock-reservado";

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public TopicExchange tiendaExchange() {
		return new TopicExchange(EXCHANGE);
	}

	@Bean
	public Queue stockReservedQueue() {
		return new Queue(Q_STOCK_RESERVED, true);
	}

	@Bean
	public Binding stockReservedBinding() {
		return BindingBuilder.bind(stockReservedQueue()).to(tiendaExchange()).with("stock.reservado");
	}

	@Bean
	public MessageConverter messageConverter() {
		return new JacksonJsonMessageConverter();
	}
}
