package es.codeurjc.dad.ddd.ejem2.domain;

import java.time.Instant;

/**
 * Evento de dominio: algo relevante para el negocio que YA ha ocurrido.
 * Se nombra en pasado (OrderPlaced, OrderCancelled...).
 */
public interface DomainEvent {

	Instant occurredOn();
}
