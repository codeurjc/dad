package es.codeurjc.dad.obs.ejem2;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

/**
 * Las métricas se pueden probar con un registro en memoria, sin Prometheus.
 */
class ShopMetricsTest {

	@Test
	void cuentaLosPedidosPorMetodoDePagoYResultado() {
		SimpleMeterRegistry registry = new SimpleMeterRegistry();
		ShopMetrics metrics = new ShopMetrics(registry);

		metrics.orderPlaced("card", 10);
		metrics.orderPlaced("card", 30);
		metrics.orderFailed("paypal", "rejected");

		assertEquals(2, registry.get("shop.orders").tag("payment", "card").tag("result", "ok").counter().count());
		assertEquals(1, registry.get("shop.orders").tag("result", "rejected").counter().count());
		assertEquals(20, registry.get("shop.order.amount").summary().mean());
	}

	@Test
	void elGaugeSubeYBaja() {
		SimpleMeterRegistry registry = new SimpleMeterRegistry();
		ShopMetrics metrics = new ShopMetrics(registry);

		metrics.cartOpened();
		metrics.cartOpened();
		metrics.cartClosed();

		assertEquals(1, registry.get("shop.carts.active").gauge().value());
	}
}
