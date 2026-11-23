package es.codeurjc.dad.eventos.ejem3.facturacion;

import java.math.BigDecimal;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

@Entity
public class Invoice {

	@Id
	@GeneratedValue
	private Long id;

	private String orderId;

	private String customer;

	private BigDecimal amount;

	protected Invoice() {
	}

	public Invoice(String orderId, String customer, BigDecimal amount) {
		this.orderId = orderId;
		this.customer = customer;
		this.amount = amount;
	}

	public Long getId() {
		return id;
	}

	public String getOrderId() {
		return orderId;
	}

	public String getCustomer() {
		return customer;
	}

	public BigDecimal getAmount() {
		return amount;
	}
}
