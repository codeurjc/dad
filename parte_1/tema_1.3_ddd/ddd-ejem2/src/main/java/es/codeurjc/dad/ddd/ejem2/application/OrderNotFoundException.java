package es.codeurjc.dad.ddd.ejem2.application;

import es.codeurjc.dad.ddd.ejem2.domain.OrderId;

public class OrderNotFoundException extends RuntimeException {

	public OrderNotFoundException(OrderId id) {
		super("No existe el pedido " + id);
	}
}
