package es.codeurjc.dad.ddd.ejer1.domain;

import java.util.Objects;

public record MemberId(String value) {

	public MemberId {
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
