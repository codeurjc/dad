package es.codeurjc.dad.ddd.ejem2.domain;

import java.util.Objects;

/**
 * Identificador tipado. Entre agregados nos referimos siempre por identidad:
 * Order guarda un CustomerId y ProductIds, nunca objetos Customer o Product.
 */
public record ProductId(String value) {

	public ProductId {
		Objects.requireNonNull(value, "value");
		if (value.isBlank()) {
			throw new IllegalArgumentException("El identificador no puede estar vacío");
		}
	}

	@Override
	public String toString() {
		return value;
	}
}
