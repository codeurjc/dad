package es.codeurjc.dad.eventos.ejem2.pedidos;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import es.codeurjc.dad.eventos.ejem2.pedidos.Events.Line;
import es.codeurjc.dad.eventos.ejem2.pedidos.Events.OrderCancelled;
import es.codeurjc.dad.eventos.ejem2.pedidos.Events.OrderPlaced;

/**
 * Gestiona los pedidos (en memoria, para simplificar) y publica sus eventos.
 */
@Service
public class OrderPublisher {

	private static final Logger log = LoggerFactory.getLogger(OrderPublisher.class);

	private final RabbitTemplate rabbit;
	private final Map<String, List<Line>> orders = new ConcurrentHashMap<>();

	public OrderPublisher(RabbitTemplate rabbit) {
		this.rabbit = rabbit;
	}

	public OrderPlaced placeOrder(String customerEmail, List<Line> lines) {
		String orderId = "P-" + UUID.randomUUID().toString().substring(0, 8);
		orders.put(orderId, List.copyOf(lines));

		BigDecimal total = lines.stream()
				.map(l -> l.unitPrice().multiply(BigDecimal.valueOf(l.quantity())))
				.reduce(BigDecimal.ZERO, BigDecimal::add);

		OrderPlaced event = new OrderPlaced(UUID.randomUUID().toString(), Instant.now(), orderId, customerEmail,
				lines, total);
		rabbit.convertAndSend(Application.EXCHANGE, "pedido.confirmado", event);
		log.info("Publicado pedido.confirmado: {}", event);
		return event;
	}

	public OrderCancelled cancelOrder(String orderId) {
		List<Line> lines = orders.remove(orderId);
		if (lines == null) {
			throw new IllegalArgumentException("No existe el pedido " + orderId);
		}
		OrderCancelled event = new OrderCancelled(UUID.randomUUID().toString(), Instant.now(), orderId, lines);
		rabbit.convertAndSend(Application.EXCHANGE, "pedido.cancelado", event);
		log.info("Publicado pedido.cancelado: {}", event);
		return event;
	}
}
