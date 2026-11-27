package es.codeurjc.dad.ddd.ejem2.application;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import es.codeurjc.dad.ddd.ejem2.domain.CustomerId;
import es.codeurjc.dad.ddd.ejem2.domain.Money;
import es.codeurjc.dad.ddd.ejem2.domain.Order;
import es.codeurjc.dad.ddd.ejem2.domain.OrderId;
import es.codeurjc.dad.ddd.ejem2.domain.OrderRepository;
import es.codeurjc.dad.ddd.ejem2.domain.ProductId;

/**
 * Servicio de aplicación: orquesta los casos de uso.
 *
 * Cada método sigue el mismo patrón y NO contiene reglas de negocio:
 * <ol>
 * <li>Cargar el agregado del repositorio.</li>
 * <li>Pedirle al agregado que haga algo (las reglas están en el agregado).</li>
 * <li>Guardar el agregado.</li>
 * <li>Publicar los eventos de dominio que se hayan producido.</li>
 * </ol>
 * Una transacción modifica un único agregado.
 */
@Service
@Transactional
public class OrderService {

	private final OrderRepository orders;
	private final DomainEventPublisher events;

	public OrderService(OrderRepository orders, DomainEventPublisher events) {
		this.orders = orders;
		this.events = events;
	}

	public OrderId createOrder(CustomerId customerId) {
		Order order = Order.create(orders.nextId(), customerId);
		orders.save(order);
		return order.id();
	}

	public void addProduct(OrderId orderId, ProductId productId, int quantity, Money unitPrice) {
		Order order = load(orderId);
		order.addProduct(productId, quantity, unitPrice);
		orders.save(order);
	}

	public void removeProduct(OrderId orderId, ProductId productId) {
		Order order = load(orderId);
		order.removeProduct(productId);
		orders.save(order);
	}

	public void placeOrder(OrderId orderId) {
		Order order = load(orderId);
		order.place();
		orders.save(order);
		events.publish(order.pullDomainEvents());
	}

	public void cancelOrder(OrderId orderId) {
		Order order = load(orderId);
		order.cancel();
		orders.save(order);
		events.publish(order.pullDomainEvents());
	}

	@Transactional(readOnly = true)
	public Order findOrder(OrderId orderId) {
		return load(orderId);
	}

	private Order load(OrderId orderId) {
		return orders.findById(orderId).orElseThrow(() -> new OrderNotFoundException(orderId));
	}
}
