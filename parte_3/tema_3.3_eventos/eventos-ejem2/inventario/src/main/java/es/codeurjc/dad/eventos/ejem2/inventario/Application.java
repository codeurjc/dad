package es.codeurjc.dad.eventos.ejem2.inventario;

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
 * Servicio de Inventario: CONSUMIDOR de eventos de pedidos.
 *
 * Cada servicio suscriptor declara SUS PROPIAS colas y las enlaza (binding) al
 * exchange del productor. Así cada suscriptor recibe una copia de cada evento
 * y puede procesarlos a su ritmo, aunque esté caído un rato (los mensajes
 * esperan en su cola).
 */
@SpringBootApplication
public class Application {

	public static final String EXCHANGE = "pedidos";
	public static final String QUEUE_PLACED = "inventario.pedido-confirmado";
	public static final String QUEUE_CANCELLED = "inventario.pedido-cancelado";

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public TopicExchange pedidosExchange() {
		return new TopicExchange(EXCHANGE);
	}

	@Bean
	public Queue placedQueue() {
		return new Queue(QUEUE_PLACED, true);
	}

	@Bean
	public Queue cancelledQueue() {
		return new Queue(QUEUE_CANCELLED, true);
	}

	@Bean
	public Binding placedBinding() {
		return BindingBuilder.bind(placedQueue()).to(pedidosExchange()).with("pedido.confirmado");
	}

	@Bean
	public Binding cancelledBinding() {
		return BindingBuilder.bind(cancelledQueue()).to(pedidosExchange()).with("pedido.cancelado");
	}

	@Bean
	public MessageConverter messageConverter() {
		return new JacksonJsonMessageConverter();
	}
}
