package es.codeurjc.dad.ddd.ejem2.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Las reglas de negocio se prueban sin Spring, sin base de datos y sin HTTP.
 */
class OrderTest {

	private Order order;

	@BeforeEach
	void setUp() {
		order = Order.create(new OrderId("o-1"), new CustomerId("c-1"));
	}

	@Test
	void unPedidoNuevoEsUnBorradorVacio() {
		assertEquals(OrderStatus.DRAFT, order.status());
		assertEquals(Money.ZERO, order.total());
	}

	@Test
	void anadirElMismoProductoAcumulaUnidades() {
		order.addProduct(new ProductId("p-1"), 2, Money.euros("10"));
		order.addProduct(new ProductId("p-1"), 3, Money.euros("10"));

		assertEquals(1, order.lines().size());
		assertEquals(5, order.units());
		assertEquals(Money.euros("50"), order.total());
	}

	@Test
	void noSePuedeSuperarElImporteMaximo() {
		order.addProduct(new ProductId("p-1"), 1, Money.euros("4999"));

		assertThrows(DomainException.class, () -> order.addProduct(new ProductId("p-2"), 1, Money.euros("2")));
		assertEquals(1, order.lines().size(), "si se viola una invariante el agregado no cambia");
	}

	@Test
	void noSePuedenTenerMasDeDiezProductosDistintos() {
		for (int i = 0; i < Order.MAX_LINES; i++) {
			order.addProduct(new ProductId("p-" + i), 1, Money.euros("1"));
		}
		assertThrows(DomainException.class, () -> order.addProduct(new ProductId("p-x"), 1, Money.euros("1")));
	}

	@Test
	void noSePuedeConfirmarUnPedidoVacio() {
		assertThrows(DomainException.class, order::place);
	}

	@Test
	void confirmarGeneraElEventoOrderPlaced() {
		order.addProduct(new ProductId("p-1"), 2, Money.euros("10"));
		order.place();

		List<DomainEvent> events = order.pullDomainEvents();
		assertEquals(1, events.size());
		OrderPlaced placed = assertInstanceOf(OrderPlaced.class, events.get(0));
		assertEquals(Money.euros("20"), placed.total());
		assertTrue(order.pullDomainEvents().isEmpty(), "los eventos solo se entregan una vez");
	}

	@Test
	void unPedidoConfirmadoNoSePuedeModificar() {
		order.addProduct(new ProductId("p-1"), 1, Money.euros("10"));
		order.place();

		assertThrows(DomainException.class, () -> order.addProduct(new ProductId("p-2"), 1, Money.euros("1")));
		assertThrows(DomainException.class, () -> order.removeProduct(new ProductId("p-1")));
	}

	@Test
	void lasLineasNoSePuedenModificarDesdeFuera() {
		order.addProduct(new ProductId("p-1"), 1, Money.euros("10"));
		assertThrows(UnsupportedOperationException.class, () -> order.lines().clear());
	}

	@Test
	void noSePuedeCancelarDosVeces() {
		order.cancel();
		assertThrows(DomainException.class, order::cancel);
	}
}
