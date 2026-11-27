package es.codeurjc.dad.eventos.ejer1.stock;

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
	public static final String Q_ORDER_CREATED = "stock.pedido-creado";
	public static final String Q_PAYMENT_REJECTED = "stock.pago-rechazado";

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public TopicExchange tiendaExchange() {
		return new TopicExchange(EXCHANGE);
	}

	@Bean
	public Queue orderCreatedQueue() {
		return new Queue(Q_ORDER_CREATED, true);
	}

	@Bean
	public Queue paymentRejectedQueue() {
		return new Queue(Q_PAYMENT_REJECTED, true);
	}

	@Bean
	public Binding orderCreatedBinding() {
		return BindingBuilder.bind(orderCreatedQueue()).to(tiendaExchange()).with("pedido.creado");
	}

	@Bean
	public Binding paymentRejectedBinding() {
		return BindingBuilder.bind(paymentRejectedQueue()).to(tiendaExchange()).with("pago.rechazado");
	}

	@Bean
	public MessageConverter messageConverter() {
		return new JacksonJsonMessageConverter();
	}
}
