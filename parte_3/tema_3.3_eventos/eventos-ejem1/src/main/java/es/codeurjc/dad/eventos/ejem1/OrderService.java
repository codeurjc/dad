package es.codeurjc.dad.eventos.ejem1;

import java.math.BigDecimal;
import java.time.Instant;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * El servicio de pedidos solo sabe que "ha ocurrido algo": publica el evento y
 * no conoce a quién le interesa (facturación, emails, puntos de fidelidad...).
 */
@Service
public class OrderService {

	/** Simulamos un fallo DESPUÉS de publicar el evento para ver qué pasa con la transacción. */
	public static final BigDecimal FRAUD_LIMIT = new BigDecimal("10000");

	private final OrderRepository orders;
	private final ApplicationEventPublisher events;

	public OrderService(OrderRepository orders, ApplicationEventPublisher events) {
		this.orders = orders;
		this.events = events;
	}

	@Transactional
	public Long placeOrder(String customerEmail, BigDecimal total) {
		Order order = orders.save(new Order(customerEmail, total));

		events.publishEvent(new OrderPlaced(order.getId(), customerEmail, total, Instant.now()));

		if (total.compareTo(FRAUD_LIMIT) > 0) {
			// La transacción hace rollback: el pedido no se guarda...
			// ...pero ¿qué ha pasado con los listeners que ya han recibido el evento?
			throw new IllegalStateException("Pedido sospechoso de fraude: " + total);
		}
		return order.getId();
	}
}
