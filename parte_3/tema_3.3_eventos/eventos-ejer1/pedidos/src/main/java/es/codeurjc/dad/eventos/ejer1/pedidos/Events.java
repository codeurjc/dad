package es.codeurjc.dad.eventos.ejer1.pedidos;

import java.math.BigDecimal;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

public final class Events {

	private Events() {
	}

	/** Publicado por Pedidos. */
	public record OrderCreated(String orderId, String customerId, String productId, int quantity,
			BigDecimal amount) {
	}

	/** Consumidos por Pedidos. */
	@JsonIgnoreProperties(ignoreUnknown = true)
	public record StockRejected(String orderId, String reason) {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record PaymentAccepted(String orderId) {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record PaymentRejected(String orderId, String reason) {
	}
}
