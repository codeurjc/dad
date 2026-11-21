package es.codeurjc.dad.eventos.ejem3.facturacion;

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

	public static final String EXCHANGE = "pedidos";
	public static final String QUEUE = "facturacion.pedido-confirmado";

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public TopicExchange pedidosExchange() {
		return new TopicExchange(EXCHANGE);
	}

	@Bean
	public Queue facturacionQueue() {
		return new Queue(QUEUE, true);
	}

	@Bean
	public Binding facturacionBinding() {
		return BindingBuilder.bind(facturacionQueue()).to(pedidosExchange()).with("pedido.confirmado");
	}

	@Bean
	public MessageConverter messageConverter() {
		return new JacksonJsonMessageConverter();
	}
}
