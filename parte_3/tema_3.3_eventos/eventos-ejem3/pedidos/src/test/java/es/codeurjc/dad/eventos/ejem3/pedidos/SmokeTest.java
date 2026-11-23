package es.codeurjc.dad.eventos.ejem3.pedidos;

import static org.junit.jupiter.api.Assertions.assertTrue;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigDecimal;

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
	void elBrokerResponde() {
		try (Connection conexion = connectionFactory.createConnection()) {
			assertTrue(conexion.isOpen());
		}
	}

	@Autowired
	private OrderService orders;

	@Autowired
	private OutboxRepository outbox;

	@Autowired
	private OutboxRelay relay;

	@Test
	void elPedidoYSuEventoSeGuardanJuntosYElRelayLoPublica() {
		String orderId = orders.placeOrder("ana", new BigDecimal("99.90"));

		OutboxMessage message = outbox.findAll().stream()
				.filter(m -> m.getAggregateId().equals(orderId))
				.findFirst().orElseThrow();
		assertTrue(message.getPayload().contains(orderId));

		relay.publishPending();

		assertEquals(0, outbox.countByPublishedAtIsNull());
	}
}
