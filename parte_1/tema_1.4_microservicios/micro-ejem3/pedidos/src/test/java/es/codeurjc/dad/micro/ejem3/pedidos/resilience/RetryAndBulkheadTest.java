package es.codeurjc.dad.micro.ejem3.pedidos.resilience;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class RetryAndBulkheadTest {

	static class Transient extends RuntimeException {
	}

	private final List<Duration> waits = new ArrayList<>();
	private final Retry retry = new Retry(3, Duration.ofMillis(100), e -> e instanceof Transient, waits::add);

	@Test
	void reintentaLosErroresTransitoriosConEsperaCreciente() {
		AtomicInteger calls = new AtomicInteger();
		String result = retry.call(() -> {
			if (calls.incrementAndGet() < 3) {
				throw new Transient();
			}
			return "ok";
		});

		assertEquals("ok", result);
		assertEquals(3, calls.get());
		assertEquals(2, waits.size());
		// 100 ms + jitter (hasta 50 ms) y después el doble: 200 ms + jitter (hasta 100 ms)
		assertTrue(waits.get(0).toMillis() >= 100 && waits.get(0).toMillis() <= 150);
		assertTrue(waits.get(1).toMillis() >= 200 && waits.get(1).toMillis() <= 300);
	}

	@Test
	void noReintentaLosErroresPermanentes() {
		AtomicInteger calls = new AtomicInteger();
		assertThrows(IllegalArgumentException.class, () -> retry.call(() -> {
			calls.incrementAndGet();
			throw new IllegalArgumentException("404");
		}));
		assertEquals(1, calls.get());
	}

	@Test
	void seRindeTrasElMaximoDeIntentos() {
		AtomicInteger calls = new AtomicInteger();
		assertThrows(Transient.class, () -> retry.call(() -> {
			calls.incrementAndGet();
			throw new Transient();
		}));
		assertEquals(3, calls.get());
	}

	@Test
	void elBulkheadRechazaCuandoNoQuedanPermisos() {
		Bulkhead bulkhead = new Bulkhead(1);
		bulkhead.call(() -> {
			// dentro de una llamada, otra concurrente no cabe
			assertThrows(Bulkhead.BulkheadFullException.class, () -> bulkhead.call(() -> "x"));
			return "ok";
		});
		assertEquals(1, bulkhead.availablePermits());
	}
}
