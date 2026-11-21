package es.codeurjc.dad.eventos.ejer1.stock;

import java.util.HashMap;
import java.util.Map;

/**
 * Almacén con reservas por pedido. Java puro, sin Spring.
 *
 * Las operaciones son IDEMPOTENTES porque los mensajes pueden llegar más de una
 * vez: reservar dos veces el mismo pedido o liberarlo dos veces no cambia nada.
 */
public class Warehouse {

	public record Reservation(String productId, int quantity) {
	}

	private final Map<String, Integer> available = new HashMap<>();
	private final Map<String, Reservation> reservations = new HashMap<>();

	public Warehouse(Map<String, Integer> initialStock) {
		available.putAll(initialStock);
	}

	/** @return true si el pedido tiene (o ya tenía) su reserva */
	public synchronized boolean reserve(String orderId, String productId, int quantity) {
		if (reservations.containsKey(orderId)) {
			return true;
		}
		int units = available.getOrDefault(productId, 0);
		if (units < quantity) {
			return false;
		}
		available.put(productId, units - quantity);
		reservations.put(orderId, new Reservation(productId, quantity));
		return true;
	}

	/** Transacción de compensación: deshace la reserva. */
	public synchronized boolean release(String orderId) {
		Reservation r = reservations.remove(orderId);
		if (r == null) {
			return false;
		}
		available.merge(r.productId(), r.quantity(), Integer::sum);
		return true;
	}

	public synchronized int available(String productId) {
		return available.getOrDefault(productId, 0);
	}
}
