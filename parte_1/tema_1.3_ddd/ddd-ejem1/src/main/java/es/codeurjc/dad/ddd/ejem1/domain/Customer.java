package es.codeurjc.dad.ddd.ejem1.domain;

import java.util.Objects;

/**
 * Entidad: un cliente.
 *
 * <ul>
 * <li>Tiene identidad (CustomerId) que se mantiene aunque cambien sus atributos.</li>
 * <li>Dos clientes son el mismo si tienen el mismo id, aunque tengan nombres
 * distintos (equals/hashCode solo usan el id).</li>
 * <li>Su estado cambia a lo largo del tiempo, pero solo a través de métodos con
 * significado en el dominio (no hay setters genéricos).</li>
 * </ul>
 */
public class Customer {

	private static final Money VIP_THRESHOLD = Money.euros("1000");

	private final CustomerId id;
	private String name;
	private EmailAddress email;
	private Address shippingAddress;
	private Money totalSpent;

	public Customer(CustomerId id, String name, EmailAddress email, Address shippingAddress) {
		this.id = Objects.requireNonNull(id, "id");
		rename(name);
		this.email = Objects.requireNonNull(email, "email");
		this.shippingAddress = Objects.requireNonNull(shippingAddress, "shippingAddress");
		this.totalSpent = Money.zero(Money.EUR);
	}

	public void rename(String newName) {
		if (newName == null || newName.isBlank()) {
			throw new IllegalArgumentException("El nombre es obligatorio");
		}
		this.name = newName.trim();
	}

	public void changeEmail(EmailAddress newEmail) {
		this.email = Objects.requireNonNull(newEmail, "newEmail");
	}

	public void moveTo(Address newAddress) {
		this.shippingAddress = Objects.requireNonNull(newAddress, "newAddress");
	}

	/** Lenguaje ubicuo: "registrar una compra", no "setTotalSpent". */
	public void registerPurchase(Money amount) {
		this.totalSpent = totalSpent.plus(amount);
	}

	/** Regla de negocio expresada dentro de la entidad que tiene los datos. */
	public boolean isVip() {
		return totalSpent.isGreaterThan(VIP_THRESHOLD);
	}

	public CustomerId id() {
		return id;
	}

	public String name() {
		return name;
	}

	public EmailAddress email() {
		return email;
	}

	public Address shippingAddress() {
		return shippingAddress;
	}

	public Money totalSpent() {
		return totalSpent;
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof Customer other && id.equals(other.id);
	}

	@Override
	public int hashCode() {
		return id.hashCode();
	}

	@Override
	public String toString() {
		return "Customer[" + id + ", " + name + ", " + email + ", vip=" + isVip() + "]";
	}
}
