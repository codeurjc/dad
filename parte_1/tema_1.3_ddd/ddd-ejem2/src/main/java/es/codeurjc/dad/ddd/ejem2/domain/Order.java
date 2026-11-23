package es.codeurjc.dad.ddd.ejem2.domain;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Raíz del agregado Pedido.
 *
 * El agregado es la frontera de consistencia: todas las invariantes de abajo se
 * cumplen SIEMPRE al terminar cualquier método público, porque toda modificación
 * pasa por la raíz.
 *
 * Invariantes:
 * <ol>
 * <li>Solo se pueden añadir o quitar productos mientras el pedido es un borrador.</li>
 * <li>Un pedido no puede tener más de {@value #MAX_LINES} líneas distintas.</li>
 * <li>El importe total no puede superar {@link #MAX_TOTAL}.</li>
 * <li>No se puede confirmar un pedido vacío.</li>
 * <li>Un pedido cancelado no se puede volver a cancelar.</li>
 * </ol>
 *
 * La clase no tiene ninguna anotación de JPA ni de Spring: el modelo de dominio
 * es Java puro y se puede probar sin arrancar nada.
 */
public class Order {

	public static final int MAX_LINES = 10;
	public static final Money MAX_TOTAL = Money.euros("5000");

	private final OrderId id;
	private final CustomerId customerId;
	private OrderStatus status;
	private final List<OrderLine> lines;

	private final List<DomainEvent> domainEvents = new ArrayList<>();
	private final Clock clock;

	private Order(OrderId id, CustomerId customerId, OrderStatus status, List<OrderLine> lines, Clock clock) {
		this.id = Objects.requireNonNull(id, "id");
		this.customerId = Objects.requireNonNull(customerId, "customerId");
		this.status = Objects.requireNonNull(status, "status");
		this.lines = new ArrayList<>(lines);
		this.clock = clock;
	}

	/** Factoría: crea un pedido nuevo, siempre en estado borrador. */
	public static Order create(OrderId id, CustomerId customerId) {
		return create(id, customerId, Clock.systemUTC());
	}

	public static Order create(OrderId id, CustomerId customerId, Clock clock) {
		return new Order(id, customerId, OrderStatus.DRAFT, List.of(), clock);
	}

	/**
	 * Reconstruye un pedido ya existente (lo usa el repositorio al leer de la
	 * base de datos). No genera eventos: no ha ocurrido nada nuevo.
	 */
	public static Order rehydrate(OrderId id, CustomerId customerId, OrderStatus status, List<OrderLine> lines) {
		return new Order(id, customerId, status, lines, Clock.systemUTC());
	}

	// ---------- Comportamiento (lenguaje ubicuo) ----------

	public void addProduct(ProductId productId, int quantity, Money unitPrice) {
		requireDraft("añadir productos");

		OrderLine newLine = new OrderLine(productId, quantity, unitPrice);
		int index = indexOf(productId);
		List<OrderLine> candidate = new ArrayList<>(lines);
		if (index >= 0) {
			candidate.set(index, candidate.get(index).withExtraUnits(quantity));
		} else {
			candidate.add(newLine);
		}

		// Comprobamos las invariantes sobre el estado candidato ANTES de aplicarlo
		if (candidate.size() > MAX_LINES) {
			throw new DomainException("Un pedido no puede tener más de " + MAX_LINES + " productos distintos");
		}
		if (totalOf(candidate).isGreaterThan(MAX_TOTAL)) {
			throw new DomainException("El pedido superaría el importe máximo de " + MAX_TOTAL);
		}
		lines.clear();
		lines.addAll(candidate);
	}

	public void removeProduct(ProductId productId) {
		requireDraft("quitar productos");
		if (!lines.removeIf(l -> l.productId().equals(productId))) {
			throw new DomainException("El pedido no contiene el producto " + productId);
		}
	}

	public void place() {
		requireDraft("confirmar el pedido");
		if (lines.isEmpty()) {
			throw new DomainException("No se puede confirmar un pedido vacío");
		}
		status = OrderStatus.PLACED;
		domainEvents.add(new OrderPlaced(id, customerId, total(), units(), Instant.now(clock)));
	}

	public void cancel() {
		if (status == OrderStatus.CANCELLED) {
			throw new DomainException("El pedido ya estaba cancelado");
		}
		status = OrderStatus.CANCELLED;
		domainEvents.add(new OrderCancelled(id, customerId, Instant.now(clock)));
	}

	// ---------- Consultas ----------

	public Money total() {
		return totalOf(lines);
	}

	public int units() {
		return lines.stream().mapToInt(OrderLine::quantity).sum();
	}

	public OrderId id() {
		return id;
	}

	public CustomerId customerId() {
		return customerId;
	}

	public OrderStatus status() {
		return status;
	}

	/** Las líneas se exponen como lista de solo lectura. */
	public List<OrderLine> lines() {
		return Collections.unmodifiableList(lines);
	}

	/**
	 * Devuelve los eventos ocurridos desde la última vez y los olvida. El
	 * servicio de aplicación los publica después de guardar el agregado.
	 */
	public List<DomainEvent> pullDomainEvents() {
		List<DomainEvent> events = List.copyOf(domainEvents);
		domainEvents.clear();
		return events;
	}

	// ---------- Auxiliares ----------

	private void requireDraft(String action) {
		if (status != OrderStatus.DRAFT) {
			throw new DomainException("No se puede " + action + " en un pedido " + status);
		}
	}

	private int indexOf(ProductId productId) {
		for (int i = 0; i < lines.size(); i++) {
			if (lines.get(i).productId().equals(productId)) {
				return i;
			}
		}
		return -1;
	}

	private static Money totalOf(List<OrderLine> lines) {
		return lines.stream().map(OrderLine::subtotal).reduce(Money.ZERO, Money::plus);
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof Order other && id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}
}
