package es.codeurjc.dad.ddd.ejem3.sales.api;

import java.util.List;

/**
 * Lenguaje publicado (Published Language) del contexto de Ventas.
 *
 * Es el contrato que Ventas ofrece a los demás contextos. Ventas se
 * compromete a mantenerlo estable aunque su modelo interno cambie. Los
 * contextos consumidores NO deben depender de ninguna otra clase de sales.
 */
public record OrderPlacedEvent(String orderId, String customerName, String street, String city,
		String postalCode, List<Item> items) {

	public record Item(String productCode, int quantity) {
	}
}
