package es.codeurjc.dad.ddd.ejem2;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import es.codeurjc.dad.ddd.ejem2.application.OrderService;
import es.codeurjc.dad.ddd.ejem2.domain.CustomerId;
import es.codeurjc.dad.ddd.ejem2.domain.Money;
import es.codeurjc.dad.ddd.ejem2.domain.Order;
import es.codeurjc.dad.ddd.ejem2.domain.OrderId;
import es.codeurjc.dad.ddd.ejem2.domain.OrderStatus;
import es.codeurjc.dad.ddd.ejem2.domain.ProductId;

/**
 * Comprobacion minima: el contexto arranca y un pedido se guarda y se recupera
 * completo a traves del repositorio JPA.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private OrderService service;

	@Test
	void unPedidoSePersisteYSeRecupera() {
		OrderId id = service.createOrder(new CustomerId("c-1"));
		service.addProduct(id, new ProductId("p-1"), 2, Money.euros("9.95"));
		service.addProduct(id, new ProductId("p-2"), 1, Money.euros("5"));
		service.placeOrder(id);

		Order order = service.findOrder(id);
		assertEquals(OrderStatus.PLACED, order.status());
		assertEquals(2, order.lines().size());
		assertEquals(Money.euros("24.90"), order.total());
	}
}
