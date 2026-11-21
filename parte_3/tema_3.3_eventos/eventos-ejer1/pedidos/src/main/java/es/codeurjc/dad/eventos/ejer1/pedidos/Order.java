package es.codeurjc.dad.eventos.ejer1.pedidos;

import java.math.BigDecimal;

/**
 * Pedido. Mientras dura la saga está PENDING: el cliente ve que su pedido
 * "se está procesando" (consistencia eventual).
 */
public class Order {

	private final String id;
	private final String customerId;
	private final String productId;
	private final int quantity;
	private final BigDecimal amount;
	private OrderStatus status = OrderStatus.PENDING;
	private String rejectionReason;

	public Order(String id, String customerId, String productId, int quantity, BigDecimal amount) {
		if (quantity <= 0 || amount.signum() <= 0) {
			throw new IllegalArgumentException("Cantidad e importe deben ser positivos");
		}
		this.id = id;
		this.customerId = customerId;
		this.productId = productId;
		this.quantity = quantity;
		this.amount = amount;
	}

	/**
	 * Los mensajes pueden llegar duplicados: si el pedido ya no está pendiente,
	 * no hacemos nada (idempotencia).
	 *
	 * @return true si ha cambiado el estado
	 */
	public boolean approve() {
		if (status != OrderStatus.PENDING) {
			return false;
		}
		status = OrderStatus.APPROVED;
		return true;
	}

	public boolean reject(String reason) {
		if (status != OrderStatus.PENDING) {
			return false;
		}
		status = OrderStatus.REJECTED;
		rejectionReason = reason;
		return true;
	}

	public String id() {
		return id;
	}

	public String customerId() {
		return customerId;
	}

	public String productId() {
		return productId;
	}

	public int quantity() {
		return quantity;
	}

	public BigDecimal amount() {
		return amount;
	}

	public OrderStatus status() {
		return status;
	}

	public String rejectionReason() {
		return rejectionReason;
	}
}
