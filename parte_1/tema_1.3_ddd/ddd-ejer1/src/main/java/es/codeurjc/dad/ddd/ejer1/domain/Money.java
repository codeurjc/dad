package es.codeurjc.dad.ddd.ejer1.domain;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Objects;

/** Value Object: euros. */
public record Money(BigDecimal amount) {

	public static final Money ZERO = new Money(BigDecimal.ZERO);

	public Money {
		Objects.requireNonNull(amount, "amount");
		if (amount.signum() < 0) {
			throw new IllegalArgumentException("Una cantidad de dinero no puede ser negativa");
		}
		amount = amount.setScale(2, RoundingMode.HALF_EVEN);
	}

	public static Money euros(String amount) {
		return new Money(new BigDecimal(amount));
	}

	public Money plus(Money other) {
		return new Money(amount.add(other.amount));
	}

	public Money minus(Money other) {
		return new Money(amount.subtract(other.amount));
	}

	public Money times(long n) {
		return new Money(amount.multiply(BigDecimal.valueOf(n)));
	}

	public boolean isZero() {
		return amount.signum() == 0;
	}

	public boolean isGreaterThan(Money other) {
		return amount.compareTo(other.amount) > 0;
	}

	@Override
	public String toString() {
		return amount.toPlainString() + " EUR";
	}
}
