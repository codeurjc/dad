package es.codeurjc.dad.ddd.ejem2.infrastructure.persistence;

import java.util.ArrayList;
import java.util.List;

import es.codeurjc.dad.ddd.ejem2.domain.OrderStatus;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

/**
 * Modelo de persistencia del agregado Order.
 *
 * Separamos el modelo de dominio (Order) del modelo de persistencia
 * (OrderJpaEntity) para que el dominio no dependa de JPA. El precio es tener
 * que traducir entre ambos (ver JpaOrderRepository). En proyectos pequeños es
 * habitual anotar directamente las clases del dominio: es una decisión
 * pragmática, no un dogma.
 *
 * Todo el agregado se guarda y se carga junto: las líneas son una
 * ElementCollection, no una entidad con repositorio propio.
 */
@Entity
@Table(name = "orders")
public class OrderJpaEntity {

	@Id
	private String id;

	private String customerId;

	@Enumerated(EnumType.STRING)
	private OrderStatus status;

	@ElementCollection(fetch = FetchType.EAGER)
	@CollectionTable(name = "order_lines", joinColumns = @JoinColumn(name = "order_id"))
	private List<OrderLineEmbeddable> lines = new ArrayList<>();

	/** Bloqueo optimista: dos transacciones no pueden pisarse el mismo agregado. */
	@Version
	private Long version;

	protected OrderJpaEntity() {
	}

	public OrderJpaEntity(String id) {
		this.id = id;
	}

	public String getId() {
		return id;
	}

	public String getCustomerId() {
		return customerId;
	}

	public void setCustomerId(String customerId) {
		this.customerId = customerId;
	}

	public OrderStatus getStatus() {
		return status;
	}

	public void setStatus(OrderStatus status) {
		this.status = status;
	}

	public List<OrderLineEmbeddable> getLines() {
		return lines;
	}

	public void replaceLines(List<OrderLineEmbeddable> newLines) {
		lines.clear();
		lines.addAll(newLines);
	}
}
