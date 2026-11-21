package es.codeurjc.dad.micro.ejem1.pedidos;

import java.math.BigDecimal;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Pedido. Guarda una COPIA del nombre y del precio del producto en el
 * momento de la compra: si mañana cambia el precio en el catálogo, el pedido
 * no debe cambiar. Además, así no dependemos del catálogo para mostrarlo.
 */
@Entity
@Table(name = "orders")
public class Order {

	@Id
	@GeneratedValue
	private Long id;

	private Long productId;

	private String productName;

	private BigDecimal unitPrice;

	private int quantity;

	protected Order() {
	}

	public Order(Long productId, String productName, BigDecimal unitPrice, int quantity) {
		this.productId = productId;
		this.productName = productName;
		this.unitPrice = unitPrice;
		this.quantity = quantity;
	}

	public BigDecimal getTotal() {
		return unitPrice.multiply(BigDecimal.valueOf(quantity));
	}

	public Long getId() {
		return id;
	}

	public Long getProductId() {
		return productId;
	}

	public String getProductName() {
		return productName;
	}

	public BigDecimal getUnitPrice() {
		return unitPrice;
	}

	public int getQuantity() {
		return quantity;
	}
}
