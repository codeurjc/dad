package es.codeurjc.dad.ddd.ejem1.domain;

import java.util.Objects;

/**
 * Value Object compuesto: una dirección postal.
 *
 * Cambiar de dirección no es "modificar" la dirección: es sustituirla por otra.
 */
public record Address(String street, String city, String postalCode, String country) {

	public Address {
		requireText(street, "street");
		requireText(city, "city");
		requireText(country, "country");
		Objects.requireNonNull(postalCode, "postalCode");
		if (!postalCode.matches("\\d{5}")) {
			throw new IllegalArgumentException("Código postal no válido: " + postalCode);
		}
	}

	private static void requireText(String value, String name) {
		if (value == null || value.isBlank()) {
			throw new IllegalArgumentException(name + " es obligatorio");
		}
	}

	public Address withStreet(String newStreet) {
		return new Address(newStreet, city, postalCode, country);
	}
}
