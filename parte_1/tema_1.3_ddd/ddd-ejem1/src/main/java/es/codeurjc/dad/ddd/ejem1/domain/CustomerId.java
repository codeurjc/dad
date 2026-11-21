package es.codeurjc.dad.ddd.ejem1.domain;

import java.util.Objects;
import java.util.UUID;

/**
 * Identificador tipado de un Customer.
 *
 * Usar un tipo propio en lugar de un UUID o un Long evita errores como pasar
 * el id de un pedido donde se esperaba el de un cliente: el compilador lo detecta.
 */
public record CustomerId(UUID value) {

	public CustomerId {
		Objects.requireNonNull(value, "value");
	}

	public static CustomerId newId() {
		return new CustomerId(UUID.randomUUID());
	}

	@Override
	public String toString() {
		return value.toString();
	}
}
