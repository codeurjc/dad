package es.codeurjc.dad.micro.ejer1.prestamos.resilience;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.function.Supplier;

/**
 * Circuit breaker (cortacircuitos), en Java puro para ver cómo funciona por
 * dentro. En producción se usaría una librería como Resilience4j.
 *
 * <pre>
 *            demasiados fallos              pasa el tiempo de espera
 * CLOSED ─────────────────────────▶ OPEN ─────────────────────────▶ HALF_OPEN
 *   ▲                                ▲                                  │
 *   │       la llamada de prueba     │   la llamada de prueba falla     │
 *   └────────────── va bien ─────────┼──────────────────────────────────┘
 *                                    └──────────────────────────────────┘
 * </pre>
 *
 * <ul>
 * <li><b>CLOSED</b>: las llamadas pasan. Se recuerda el resultado de las
 * últimas N; si la proporción de fallos supera el umbral, se abre.</li>
 * <li><b>OPEN</b>: las llamadas fallan INMEDIATAMENTE sin llegar al servicio
 * remoto (no lo saturamos más y no hacemos esperar al usuario).</li>
 * <li><b>HALF_OPEN</b>: pasado un tiempo, se deja pasar una llamada de prueba.
 * Si va bien se cierra; si falla, se vuelve a abrir.</li>
 * </ul>
 */
public class CircuitBreaker {

	public enum State {
		CLOSED, OPEN, HALF_OPEN
	}

	private final double failureThreshold;
	private final int windowSize;
	private final Duration openDuration;
	private final Clock clock;

	private State state = State.CLOSED;
	private final Deque<Boolean> window = new ArrayDeque<>();
	private Instant openedAt;
	private boolean trialInProgress;

	public CircuitBreaker(double failureThreshold, int windowSize, Duration openDuration, Clock clock) {
		this.failureThreshold = failureThreshold;
		this.windowSize = windowSize;
		this.openDuration = openDuration;
		this.clock = clock;
	}

	public <T> T call(Supplier<T> action) {
		acquirePermission();
		try {
			T result = action.get();
			onResult(true);
			return result;
		} catch (RuntimeException e) {
			onResult(false);
			throw e;
		}
	}

	private synchronized void acquirePermission() {
		if (state == State.OPEN) {
			if (clock.instant().isBefore(openedAt.plus(openDuration))) {
				throw new CallNotPermittedException();
			}
			state = State.HALF_OPEN;
		}
		if (state == State.HALF_OPEN) {
			if (trialInProgress) {
				throw new CallNotPermittedException(); // solo una llamada de prueba a la vez
			}
			trialInProgress = true;
		}
	}

	private synchronized void onResult(boolean success) {
		if (state == State.HALF_OPEN) {
			trialInProgress = false;
			if (success) {
				state = State.CLOSED;
				window.clear();
			} else {
				open();
			}
			return;
		}
		window.addLast(success);
		if (window.size() > windowSize) {
			window.removeFirst();
		}
		if (window.size() == windowSize && failureRate() >= failureThreshold) {
			open();
		}
	}

	private void open() {
		state = State.OPEN;
		openedAt = clock.instant();
		window.clear();
	}

	private double failureRate() {
		return window.stream().filter(ok -> !ok).count() / (double) window.size();
	}

	public synchronized State state() {
		if (state == State.OPEN && !clock.instant().isBefore(openedAt.plus(openDuration))) {
			return State.HALF_OPEN;
		}
		return state;
	}

	public static class CallNotPermittedException extends RuntimeException {

		public CallNotPermittedException() {
			super("Circuito abierto: llamada rechazada sin intentarla");
		}
	}
}
