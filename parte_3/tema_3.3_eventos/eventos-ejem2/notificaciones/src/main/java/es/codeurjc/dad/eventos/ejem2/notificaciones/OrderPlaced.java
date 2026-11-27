package es.codeurjc.dad.eventos.ejem2.notificaciones;

import java.math.BigDecimal;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Lo que Notificaciones necesita saber de un pedido confirmado. Cada
 * consumidor define su propia vista del evento (tolerant reader).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrderPlaced(String orderId, String customerEmail, BigDecimal total) {
}
