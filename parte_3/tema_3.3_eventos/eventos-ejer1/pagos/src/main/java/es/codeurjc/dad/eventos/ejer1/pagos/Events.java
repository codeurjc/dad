package es.codeurjc.dad.eventos.ejer1.pagos;

import java.math.BigDecimal;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

public final class Events {

	private Events() {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record StockReserved(String orderId, String customerId, BigDecimal amount) {
	}

	public record PaymentAccepted(String orderId) {
	}

	public record PaymentRejected(String orderId, String reason) {
	}
}
