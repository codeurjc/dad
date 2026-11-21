package es.codeurjc.dad.eventos.ejem2.notificaciones;

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
 * Servicio de Notificaciones: otro CONSUMIDOR de los eventos de Pedidos.
 *
 * <ul>
 * <li>Cola "notificaciones.pedido-confirmado": solo pedidos confirmados.</li>
 * <li>Cola "notificaciones.auditoria": enlazada con el patrón "pedido.#", recibe
 * TODOS los eventos de pedidos, incluidos los que se añadan en el futuro.</li>
 * </ul>
 */
@SpringBootApplication
public class Application {

	public static final String EXCHANGE = "pedidos";
	public static final String QUEUE_EMAILS = "notificaciones.pedido-confirmado";
	public static final String QUEUE_AUDIT = "notificaciones.auditoria";

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public TopicExchange pedidosExchange() {
		return new TopicExchange(EXCHANGE);
	}

	@Bean
	public Queue emailsQueue() {
		return new Queue(QUEUE_EMAILS, true);
	}

	@Bean
	public Queue auditQueue() {
		return new Queue(QUEUE_AUDIT, true);
	}

	@Bean
	public Binding emailsBinding() {
		return BindingBuilder.bind(emailsQueue()).to(pedidosExchange()).with("pedido.confirmado");
	}

	@Bean
	public Binding auditBinding() {
		// '*' sustituye exactamente una palabra; '#' sustituye cero o más palabras
		return BindingBuilder.bind(auditQueue()).to(pedidosExchange()).with("pedido.#");
	}

	@Bean
	public MessageConverter messageConverter() {
		return new JacksonJsonMessageConverter();
	}
}
