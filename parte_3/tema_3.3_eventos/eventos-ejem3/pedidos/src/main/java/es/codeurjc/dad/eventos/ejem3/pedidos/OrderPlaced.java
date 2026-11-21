package es.codeurjc.dad.eventos.ejem3.pedidos;

import java.math.BigDecimal;
import java.time.Instant;

public record OrderPlaced(String orderId, String customer, BigDecimal amount, Instant occurredAt) {
}
