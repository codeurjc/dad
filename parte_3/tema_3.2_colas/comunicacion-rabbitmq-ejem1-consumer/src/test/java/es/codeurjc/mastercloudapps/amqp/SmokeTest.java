package es.codeurjc.mastercloudapps.amqp;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.amqp.rabbit.connection.Connection;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.rabbitmq.RabbitMQContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Comprobacion minima: el contexto arranca y el broker responde.
 */
@SpringBootTest
@Testcontainers
class SmokeTest {

	@Container
	@ServiceConnection
	static RabbitMQContainer rabbit = new RabbitMQContainer("rabbitmq:3.13-management");

	@Autowired
	private ConnectionFactory connectionFactory;

	@Test
	void elContextoArranca() {
	}

	@Test
	void laColaResponde() {
		try (Connection conexion = connectionFactory.createConnection()) {
			assertTrue(conexion.isOpen());
		}
	}
}
