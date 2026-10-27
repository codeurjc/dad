package es.codeurjc.mastercloudapps.amqp;

import org.springframework.amqp.core.Queue;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Bean
	public Queue myQueue() {
    	return new Queue("messagesJson", false);
	}

	@Bean
	public MessageConverter messageConverter() {
		return new JacksonJsonMessageConverter();
	}
}
