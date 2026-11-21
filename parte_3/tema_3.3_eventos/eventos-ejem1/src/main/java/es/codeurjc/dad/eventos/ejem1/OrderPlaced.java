package es.codeurjc.dad.eventos.ejem1;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Evento: un pedido ha sido confirmado. Inmutable y nombrado en pasado.
 */
public record OrderPlaced(Long orderId, String customerEmail, BigDecimal total, Instant occurredAt) {
}
