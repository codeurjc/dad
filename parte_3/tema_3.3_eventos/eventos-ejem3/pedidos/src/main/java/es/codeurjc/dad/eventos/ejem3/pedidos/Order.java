package es.codeurjc.dad.eventos.ejem3.pedidos;

import java.math.BigDecimal;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "orders")
public class Order {

	@Id
	private String id;

	private String customer;

	private BigDecimal amount;

	protected Order() {
	}

	public Order(String id, String customer, BigDecimal amount) {
		this.id = id;
		this.customer = customer;
		this.amount = amount;
	}

	public String getId() {
		return id;
	}

	public String getCustomer() {
		return customer;
	}

	public BigDecimal getAmount() {
		return amount;
	}
}
