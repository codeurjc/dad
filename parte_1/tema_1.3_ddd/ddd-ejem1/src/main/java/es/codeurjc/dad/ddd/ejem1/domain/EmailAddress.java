package es.codeurjc.dad.ddd.ejem1.domain;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value Object: una dirección de correo válida.
 *
 * Si un método recibe un EmailAddress, sabe que el email ya está validado y
 * normalizado. La validación ocurre una sola vez, al construir el objeto.
 */
public record EmailAddress(String value) {

	private static final Pattern FORMAT = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

	public EmailAddress {
		Objects.requireNonNull(value, "value");
		value = value.trim().toLowerCase(Locale.ROOT);
		if (!FORMAT.matcher(value).matches()) {
			throw new IllegalArgumentException("Email no válido: " + value);
		}
	}

	public String domain() {
		return value.substring(value.indexOf('@') + 1);
	}

	@Override
	public String toString() {
		return value;
	}
}
