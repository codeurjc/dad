package es.codeurjc.dad.eventos.ejer1.stock;

import java.math.BigDecimal;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

public final class Events {

	private Events() {
	}

	// Consumidos por Stock

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record OrderCreated(String orderId, String customerId, String productId, int quantity,
			BigDecimal amount) {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record PaymentRejected(String orderId, String reason) {
	}

	// Publicados por Stock. StockReserved lleva cliente e importe para que Pagos
	// no tenga que preguntar a Pedidos (event-carried state transfer).

	public record StockReserved(String orderId, String customerId, BigDecimal amount) {
	}

	public record StockRejected(String orderId, String reason) {
	}
}
