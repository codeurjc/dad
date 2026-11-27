package es.codeurjc.dad.ddd.ejem2.infrastructure.persistence;

import java.math.BigDecimal;

import jakarta.persistence.Embeddable;

@Embeddable
public class OrderLineEmbeddable {

	private String productId;
	private int quantity;
	private BigDecimal unitPrice;

	protected OrderLineEmbeddable() {
	}

	public OrderLineEmbeddable(String productId, int quantity, BigDecimal unitPrice) {
		this.productId = productId;
		this.quantity = quantity;
		this.unitPrice = unitPrice;
	}

	public String getProductId() {
		return productId;
	}

	public int getQuantity() {
		return quantity;
	}

	public BigDecimal getUnitPrice() {
		return unitPrice;
	}
}
