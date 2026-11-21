package es.codeurjc.dad.eventos.ejem4.query;

import java.math.BigDecimal;
import java.time.Instant;

/** Modelo de lectura: una línea del extracto. */
public record Movement(Instant date, String concept, BigDecimal amount, BigDecimal balanceAfter) {
}
