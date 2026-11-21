package es.codeurjc.dad.ddd.ejem2.domain;

/**
 * Ciclo de vida de un pedido.
 *
 * DRAFT --place()--> PLACED --cancel()--> CANCELLED
 *   \______________cancel()______________/
 */
public enum OrderStatus {
	DRAFT, PLACED, CANCELLED
}
