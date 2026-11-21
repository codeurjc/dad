package es.codeurjc.dad.eventos.ejem1;

import java.math.BigDecimal;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "orders")
public class Order {

	@Id
	@GeneratedValue
	private Long id;

	private String customerEmail;

	private BigDecimal total;

	protected Order() {
	}

	public Order(String customerEmail, BigDecimal total) {
		this.customerEmail = customerEmail;
		this.total = total;
	}

	public Long getId() {
		return id;
	}

	public String getCustomerEmail() {
		return customerEmail;
	}

	public BigDecimal getTotal() {
		return total;
	}
}
