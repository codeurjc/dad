package es.codeurjc.dad.eventos.ejem2.pedidos;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

/**
 * Eventos que publica el servicio de Pedidos. Son su contrato público.
 *
 * Event-carried state transfer: el evento lleva todos los datos que los
 * consumidores necesitan, para que no tengan que llamar a Pedidos por REST.
 */
public final class Events {

	private Events() {
	}

	public record Line(String product, int quantity, BigDecimal unitPrice) {
	}

	public record OrderPlaced(String eventId, Instant occurredAt, String orderId, String customerEmail,
			List<Line> lines, BigDecimal total) {
	}

	public record OrderCancelled(String eventId, Instant occurredAt, String orderId, List<Line> lines) {
	}
}
