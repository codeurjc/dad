package es.codeurjc.dad.eventos.ejem1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Comprobacion minima y, de paso, demostracion de cuando se ejecuta cada tipo
 * de listener.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private OrderService service;

	@Autowired
	private OrderRepository orders;

	@Autowired
	private EventLog eventLog;

	@Test
	void unPedidoCorrectoLlegaATodosLosListeners() throws InterruptedException {
		Long id = service.placeOrder("ana@urjc.es", new BigDecimal("120"));

		assertTrue(eventLog.contains("factura:" + id));
		assertTrue(eventLog.contains("email:" + id));
		assertTrue(waitFor("puntos:" + id), "el listener asincrono termina un poco despues");
	}

	@Test
	void siLaTransaccionFallaSoloSeEjecutaElListenerSincrono() throws InterruptedException {
		long ordersBefore = orders.count();
		int logBefore = eventLog.entries().size();

		assertThrows(IllegalStateException.class,
				() -> service.placeOrder("eva@urjc.es", new BigDecimal("20000")));
		Thread.sleep(1000); // damos tiempo a un posible listener asincrono

		assertEquals(ordersBefore, orders.count(), "el pedido no se ha guardado (rollback)");
		List<String> nuevas = eventLog.entries().subList(logBefore, eventLog.entries().size());
		assertEquals(1, nuevas.size(), "solo se ha ejecutado un listener: " + nuevas);
		assertTrue(nuevas.get(0).startsWith("factura:"), "el @EventListener ya se habia ejecutado");
	}

	private boolean waitFor(String entry) throws InterruptedException {
		for (int i = 0; i < 50 && !eventLog.contains(entry); i++) {
			Thread.sleep(100);
		}
		return eventLog.contains(entry);
	}
}
