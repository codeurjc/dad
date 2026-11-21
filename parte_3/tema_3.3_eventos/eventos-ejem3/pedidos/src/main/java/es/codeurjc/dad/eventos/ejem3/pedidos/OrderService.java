package es.codeurjc.dad.eventos.ejem3.pedidos;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tools.jackson.databind.ObjectMapper;

/**
 * Guarda el pedido y el evento en la MISMA transacción local.
 *
 * Lo que NO hacemos (problema de la doble escritura / dual write):
 *
 * <pre>
 * orders.save(order);                       // 1. base de datos
 * rabbit.convertAndSend(..., event);        // 2. broker
 * </pre>
 *
 * Si la aplicación falla entre 1 y 2, el pedido existe pero nadie se entera.
 * Si publicamos antes de guardar y el guardado falla, anunciamos un pedido que
 * no existe. No hay transacción distribuida entre la BD y RabbitMQ.
 */
@Service
public class OrderService {

	private final OrderRepository orders;
	private final OutboxRepository outbox;
	private final ObjectMapper json;

	public OrderService(OrderRepository orders, OutboxRepository outbox, ObjectMapper json) {
		this.orders = orders;
		this.outbox = outbox;
		this.json = json;
	}

	@Transactional
	public String placeOrder(String customer, BigDecimal amount) {
		String orderId = "P-" + UUID.randomUUID().toString().substring(0, 8);
		orders.save(new Order(orderId, customer, amount));

		OrderPlaced event = new OrderPlaced(orderId, customer, amount, Instant.now());
		outbox.save(new OutboxMessage(UUID.randomUUID().toString(), orderId, "pedido.confirmado",
				json.writeValueAsString(event), Instant.now()));

		return orderId;
	}
}
