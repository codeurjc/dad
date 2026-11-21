package es.codeurjc.dad.eventos.ejem4.query;

import java.math.BigDecimal;
import java.time.Instant;

/** Modelo de lectura: lo que muestra la pantalla "mis cuentas". */
public record AccountSummary(String accountId, String owner, BigDecimal balance, int movements,
		Instant lastMovementAt, boolean open) {
}
