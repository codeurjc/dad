package es.codeurjc.dad.eventos.ejer1.pedidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;

import org.junit.jupiter.api.Test;

class OrderTest {

	private final Order order = new Order("P-1", "ana", "taza", 1, new BigDecimal("8"));

	@Test
	void unPedidoNuevoEstaPendiente() {
		assertEquals(OrderStatus.PENDING, order.status());
	}

	@Test
	void unaVezDecididoElEstadoNoCambia() {
		assertTrue(order.reject("sin stock"));
		assertFalse(order.approve(), "un mensaje tardío o duplicado no cambia el resultado");
		assertEquals(OrderStatus.REJECTED, order.status());
	}
}
