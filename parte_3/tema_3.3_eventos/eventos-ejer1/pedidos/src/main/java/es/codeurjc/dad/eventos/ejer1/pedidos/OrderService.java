package es.codeurjc.dad.eventos.ejer1.pedidos;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import es.codeurjc.dad.eventos.ejer1.pedidos.Events.OrderCreated;
import es.codeurjc.dad.eventos.ejer1.pedidos.Events.PaymentAccepted;
import es.codeurjc.dad.eventos.ejer1.pedidos.Events.PaymentRejected;
import es.codeurjc.dad.eventos.ejer1.pedidos.Events.StockRejected;

/**
 * Participante de la saga coreografiada:
 *
 * <pre>
 * crear pedido ──pedido.creado──▶ (Stock)
 * stock.rechazado ─▶ RECHAZADO
 * pago.aceptado   ─▶ APROBADO
 * pago.rechazado  ─▶ RECHAZADO   (Stock compensa liberando la reserva)
 * </pre>
 */
@Service
public class OrderService {

	private static final Logger log = LoggerFactory.getLogger(OrderService.class);

	private final RabbitTemplate rabbit;
	private final Map<String, Order> orders = new ConcurrentHashMap<>();

	public OrderService(RabbitTemplate rabbit) {
		this.rabbit = rabbit;
	}

	public Order createOrder(String customerId, String productId, int quantity, BigDecimal amount) {
		Order order = new Order("P-" + UUID.randomUUID().toString().substring(0, 8), customerId, productId,
				quantity, amount);
		orders.put(order.id(), order);
		rabbit.convertAndSend(Application.EXCHANGE, "pedido.creado",
				new OrderCreated(order.id(), customerId, productId, quantity, amount));
		log.info("Pedido {} creado (PENDING)", order.id());
		return order;
	}

	public Optional<Order> find(String orderId) {
		return Optional.ofNullable(orders.get(orderId));
	}

	@RabbitListener(queues = Application.Q_STOCK_REJECTED)
	public void on(StockRejected event) {
		reject(event.orderId(), "Sin stock: " + event.reason());
	}

	@RabbitListener(queues = Application.Q_PAYMENT_REJECTED)
	public void on(PaymentRejected event) {
		reject(event.orderId(), "Pago rechazado: " + event.reason());
	}

	@RabbitListener(queues = Application.Q_PAYMENT_ACCEPTED)
	public void on(PaymentAccepted event) {
		find(event.orderId()).ifPresent(order -> {
			if (order.approve()) {
				log.info("Pedido {} APROBADO", order.id());
			}
		});
	}

	private void reject(String orderId, String reason) {
		find(orderId).ifPresent(order -> {
			if (order.reject(reason)) {
				log.info("Pedido {} RECHAZADO: {}", order.id(), reason);
			}
		});
	}
}
