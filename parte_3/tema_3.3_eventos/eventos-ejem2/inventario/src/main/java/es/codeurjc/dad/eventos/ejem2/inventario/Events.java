package es.codeurjc.dad.eventos.ejem2.inventario;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Copia LOCAL de los eventos de Pedidos, solo con los campos que le interesan
 * a Inventario (no necesita el email ni los precios).
 *
 * Tolerant reader: ignoramos los campos desconocidos. Así, si Pedidos añade
 * campos nuevos a sus eventos, Inventario no se rompe.
 */
public final class Events {

	private Events() {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record Line(String product, int quantity) {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record OrderPlaced(String eventId, String orderId, List<Line> lines) {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record OrderCancelled(String eventId, String orderId, List<Line> lines) {
	}
}
