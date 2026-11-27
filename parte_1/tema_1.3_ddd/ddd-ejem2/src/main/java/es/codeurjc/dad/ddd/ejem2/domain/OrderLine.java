package es.codeurjc.dad.ddd.ejem2.domain;

import java.util.Objects;

/**
 * Línea de pedido. Forma parte del agregado Order y solo se modifica a través
 * de él (nadie fuera del agregado obtiene una referencia modificable).
 *
 * La modelamos como Value Object inmutable: "cambiar la cantidad" es sustituir
 * la línea por otra con la nueva cantidad.
 */
public record OrderLine(ProductId productId, int quantity, Money unitPrice) {

	public OrderLine {
		Objects.requireNonNull(productId, "productId");
		Objects.requireNonNull(unitPrice, "unitPrice");
		if (quantity <= 0) {
			throw new DomainException("La cantidad debe ser positiva: " + quantity);
		}
	}

	public Money subtotal() {
		return unitPrice.times(quantity);
	}

	OrderLine withExtraUnits(int extra) {
		return new OrderLine(productId, quantity + extra, unitPrice);
	}
}
