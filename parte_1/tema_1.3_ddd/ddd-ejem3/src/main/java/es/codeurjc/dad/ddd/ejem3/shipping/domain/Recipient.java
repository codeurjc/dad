package es.codeurjc.dad.ddd.ejem3.shipping.domain;

/**
 * Destinatario. Lo que para Ventas es un "cliente", para Logística es un
 * "destinatario": la misma persona, otro concepto, otro modelo. Logística no
 * necesita su historial de compras ni su crédito; necesita saber dónde entregar.
 */
public record Recipient(String name, String street, String city, String postalCode) {

	public Recipient {
		if (postalCode == null || !postalCode.matches("\\d{5}")) {
			throw new IllegalArgumentException("Código postal no válido: " + postalCode);
		}
	}
}
