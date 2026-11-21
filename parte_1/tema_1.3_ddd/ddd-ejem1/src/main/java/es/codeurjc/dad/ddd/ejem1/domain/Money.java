package es.codeurjc.dad.ddd.ejem1.domain;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Currency;
import java.util.Objects;

/**
 * Value Object: una cantidad de dinero en una divisa.
 *
 * <ul>
 * <li>No tiene identidad: dos Money con la misma cantidad y divisa son iguales.</li>
 * <li>Es inmutable: las operaciones devuelven un Money nuevo.</li>
 * <li>Se valida a sí mismo: no puede existir un Money inválido.</li>
 * <li>Encapsula comportamiento del dominio (sumar, multiplicar...) en lugar de
 * dejar BigDecimal "sueltos" por el código (primitive obsession).</li>
 * </ul>
 *
 * Los records de Java encajan muy bien con los Value Objects: generan
 * equals/hashCode basados en los atributos y sus campos son finales.
 */
public record Money(BigDecimal amount, Currency currency) {

	public static final Currency EUR = Currency.getInstance("EUR");

	public Money {
		Objects.requireNonNull(amount, "amount");
		Objects.requireNonNull(currency, "currency");
		if (amount.signum() < 0) {
			throw new IllegalArgumentException("Una cantidad de dinero no puede ser negativa: " + amount);
		}
		// Normalizamos la escala para que 10 y 10.00 sean el mismo valor
		amount = amount.setScale(currency.getDefaultFractionDigits(), RoundingMode.HALF_EVEN);
	}

	public static Money euros(String amount) {
		return new Money(new BigDecimal(amount), EUR);
	}

	public static Money zero(Currency currency) {
		return new Money(BigDecimal.ZERO, currency);
	}

	public Money plus(Money other) {
		checkSameCurrency(other);
		return new Money(amount.add(other.amount), currency);
	}

	public Money minus(Money other) {
		checkSameCurrency(other);
		return new Money(amount.subtract(other.amount), currency);
	}

	public Money times(int quantity) {
		return new Money(amount.multiply(BigDecimal.valueOf(quantity)), currency);
	}

	public boolean isGreaterThan(Money other) {
		checkSameCurrency(other);
		return amount.compareTo(other.amount) > 0;
	}

	private void checkSameCurrency(Money other) {
		if (!currency.equals(other.currency)) {
			throw new IllegalArgumentException(
					"No se pueden operar cantidades en " + currency + " y " + other.currency);
		}
	}

	@Override
	public String toString() {
		return amount.toPlainString() + " " + currency.getCurrencyCode();
	}
}
