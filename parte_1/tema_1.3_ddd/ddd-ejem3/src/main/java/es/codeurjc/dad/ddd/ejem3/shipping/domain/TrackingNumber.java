package es.codeurjc.dad.ddd.ejem3.shipping.domain;

import java.util.Objects;

/** Número de seguimiento que asigna el transportista. */
public record TrackingNumber(String value) {

	public TrackingNumber {
		Objects.requireNonNull(value, "value");
		if (value.isBlank()) {
			throw new IllegalArgumentException("Número de seguimiento vacío");
		}
	}
}
