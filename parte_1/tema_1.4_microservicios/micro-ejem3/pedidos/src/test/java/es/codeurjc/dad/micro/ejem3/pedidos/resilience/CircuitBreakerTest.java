package es.codeurjc.dad.micro.ejem3.pedidos.resilience;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import es.codeurjc.dad.micro.ejem3.pedidos.resilience.CircuitBreaker.CallNotPermittedException;
import es.codeurjc.dad.micro.ejem3.pedidos.resilience.CircuitBreaker.State;

class CircuitBreakerTest {

	/** Reloj que avanza solo cuando el test quiere. */
	static class MutableClock extends Clock {

		private Instant now = Instant.parse("2026-11-21T10:00:00Z");

		void advance(Duration d) {
			now = now.plus(d);
		}

		@Override
		public Instant instant() {
			return now;
		}

		@Override
		public java.time.ZoneId getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(java.time.ZoneId zone) {
			return this;
		}
	}

	private final MutableClock clock = new MutableClock();
	private final CircuitBreaker cb = new CircuitBreaker(0.5, 4, Duration.ofSeconds(10), clock);
	private final AtomicInteger remoteCalls = new AtomicInteger();

	private String ok() {
		remoteCalls.incrementAndGet();
		return "ok";
	}

	private String fail() {
		remoteCalls.incrementAndGet();
		throw new IllegalStateException("fallo remoto");
	}

	private void failTimes(int n) {
		for (int i = 0; i < n; i++) {
			assertThrows(IllegalStateException.class, () -> cb.call(this::fail));
		}
	}

	@Test
	void seAbreAlSuperarElUmbralDeFallos() {
		cb.call(this::ok);
		cb.call(this::ok);
		failTimes(2); // 2 de 4 = 50 %

		assertEquals(State.OPEN, cb.state());
	}

	@Test
	void abiertoRechazaSinLlamarAlServicioRemoto() {
		failTimes(4);
		int before = remoteCalls.get();

		assertThrows(CallNotPermittedException.class, () -> cb.call(this::ok));
		assertEquals(before, remoteCalls.get(), "no se ha llegado a llamar");
	}

	@Test
	void trasLaEsperaUnaLlamadaDePruebaCorrectaLoCierra() {
		failTimes(4);
		clock.advance(Duration.ofSeconds(11));
		assertEquals(State.HALF_OPEN, cb.state());

		assertEquals("ok", cb.call(this::ok));
		assertEquals(State.CLOSED, cb.state());
	}

	@Test
	void siLaLlamadaDePruebaFallaVuelveAAbrirse() {
		failTimes(4);
		clock.advance(Duration.ofSeconds(11));

		failTimes(1);
		assertEquals(State.OPEN, cb.state());
		assertThrows(CallNotPermittedException.class, () -> cb.call(this::ok));
	}
}
