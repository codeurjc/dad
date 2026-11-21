package es.codeurjc.dad.ddd.ejem2.infrastructure.persistence;

import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Repository;

import es.codeurjc.dad.ddd.ejem2.domain.CustomerId;
import es.codeurjc.dad.ddd.ejem2.domain.Money;
import es.codeurjc.dad.ddd.ejem2.domain.Order;
import es.codeurjc.dad.ddd.ejem2.domain.OrderId;
import es.codeurjc.dad.ddd.ejem2.domain.OrderLine;
import es.codeurjc.dad.ddd.ejem2.domain.OrderRepository;
import es.codeurjc.dad.ddd.ejem2.domain.ProductId;

/**
 * Adaptador de persistencia: implementa el puerto OrderRepository del dominio
 * usando Spring Data JPA y traduce entre el modelo de dominio y el de JPA.
 */
@Repository
public class JpaOrderRepository implements OrderRepository {

	private final SpringDataOrderRepository jpa;

	public JpaOrderRepository(SpringDataOrderRepository jpa) {
		this.jpa = jpa;
	}

	@Override
	public OrderId nextId() {
		return new OrderId(UUID.randomUUID().toString());
	}

	@Override
	public Optional<Order> findById(OrderId id) {
		return jpa.findById(id.value()).map(JpaOrderRepository::toDomain);
	}

	@Override
	public void save(Order order) {
		OrderJpaEntity entity = jpa.findById(order.id().value())
				.orElseGet(() -> new OrderJpaEntity(order.id().value()));
		entity.setCustomerId(order.customerId().value());
		entity.setStatus(order.status());
		entity.replaceLines(order.lines().stream()
				.map(l -> new OrderLineEmbeddable(l.productId().value(), l.quantity(), l.unitPrice().amount()))
				.toList());
		jpa.save(entity);
	}

	private static Order toDomain(OrderJpaEntity e) {
		return Order.rehydrate(
				new OrderId(e.getId()),
				new CustomerId(e.getCustomerId()),
				e.getStatus(),
				e.getLines().stream()
						.map(l -> new OrderLine(new ProductId(l.getProductId()), l.getQuantity(),
								new Money(l.getUnitPrice())))
						.toList());
	}
}
