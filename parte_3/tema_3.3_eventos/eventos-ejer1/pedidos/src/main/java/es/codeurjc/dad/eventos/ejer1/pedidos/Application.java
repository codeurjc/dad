package es.codeurjc.dad.eventos.ejer1.pedidos;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Servicio de Pedidos. Inicia la saga publicando "pedido.creado" y la termina
 * aprobando o rechazando el pedido según los eventos de Stock y Pagos.
 */
@SpringBootApplication
public class Application {

	public static final String EXCHANGE = "tienda";
	public static final String Q_STOCK_REJECTED = "pedidos.stock-rechazado";
	public static final String Q_PAYMENT_ACCEPTED = "pedidos.pago-aceptado";
	public static final String Q_PAYMENT_REJECTED = "pedidos.pago-rechazado";

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public TopicExchange tiendaExchange() {
		return new TopicExchange(EXCHANGE);
	}

	@Bean
	public Queue stockRejectedQueue() {
		return new Queue(Q_STOCK_REJECTED, true);
	}

	@Bean
	public Queue paymentAcceptedQueue() {
		return new Queue(Q_PAYMENT_ACCEPTED, true);
	}

	@Bean
	public Queue paymentRejectedQueue() {
		return new Queue(Q_PAYMENT_REJECTED, true);
	}

	@Bean
	public Binding stockRejectedBinding() {
		return BindingBuilder.bind(stockRejectedQueue()).to(tiendaExchange()).with("stock.rechazado");
	}

	@Bean
	public Binding paymentAcceptedBinding() {
		return BindingBuilder.bind(paymentAcceptedQueue()).to(tiendaExchange()).with("pago.aceptado");
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
