package es.codeurjc.dad.obs.ejem2;

import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

/**
 * Métricas de NEGOCIO de la tienda (las técnicas, como las de HTTP o la JVM,
 * las publica Spring Boot automáticamente).
 *
 * Los cuatro tipos básicos de Micrometer:
 * <ul>
 * <li><b>Counter</b>: solo crece (pedidos realizados).</li>
 * <li><b>Gauge</b>: valor que sube y baja, se lee cuando se consulta (carritos activos).</li>
 * <li><b>Timer</b>: duración y número de eventos (tiempo del pago).</li>
 * <li><b>DistributionSummary</b>: distribución de valores que no son tiempos (importe).</li>
 * </ul>
 *
 * Las etiquetas (tags) permiten desglosar: pedidos por método de pago. Deben
 * tener POCOS valores posibles: nunca el id del usuario o del pedido
 * (explosión de cardinalidad).
 */
@Component
public class ShopMetrics {

	private final MeterRegistry registry;
	private final AtomicInteger activeCarts = new AtomicInteger();
	private final Timer paymentTimer;
	private final DistributionSummary orderAmount;

	public ShopMetrics(MeterRegistry registry) {
		this.registry = registry;
		Gauge.builder("shop.carts.active", activeCarts, AtomicInteger::get)
				.description("Carritos con productos que aún no se han pagado")
				.register(registry);
		this.paymentTimer = Timer.builder("shop.payment.duration")
				.description("Tiempo que tarda la pasarela de pago")
				.publishPercentileHistogram()
				.register(registry);
		this.orderAmount = DistributionSummary.builder("shop.order.amount")
				.description("Importe de los pedidos")
				.baseUnit("euros")
				.publishPercentileHistogram()
				.register(registry);
	}

	public void orderPlaced(String paymentMethod, double amount) {
		Counter.builder("shop.orders")
				.description("Pedidos realizados")
				.tag("payment", paymentMethod)
				.tag("result", "ok")
				.register(registry)
				.increment();
		orderAmount.record(amount);
	}

	public void orderFailed(String paymentMethod, String reason) {
		Counter.builder("shop.orders")
				.description("Pedidos realizados")
				.tag("payment", paymentMethod)
				.tag("result", reason)
				.register(registry)
				.increment();
	}

	public Timer paymentTimer() {
		return paymentTimer;
	}

	public void cartOpened() {
		activeCarts.incrementAndGet();
	}

	public void cartClosed() {
		activeCarts.decrementAndGet();
	}
}
