package es.codeurjc.dad.micro.ejem3.pedidos.resilience;

import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

/**
 * Bulkhead (mamparo): limita cuántas llamadas concurrentes puede haber hacia
 * una dependencia. Si el catálogo se vuelve lento, como mucho N hilos se
 * quedan esperándolo; el resto del servicio sigue teniendo hilos libres.
 */
public class Bulkhead {

	private final Semaphore permits;

	public Bulkhead(int maxConcurrentCalls) {
		this.permits = new Semaphore(maxConcurrentCalls);
	}

	public <T> T call(Supplier<T> action) {
		if (!permits.tryAcquire()) {
			throw new BulkheadFullException();
		}
		try {
			return action.get();
		} finally {
			permits.release();
		}
	}

	public int availablePermits() {
		return permits.availablePermits();
	}

	public static class BulkheadFullException extends RuntimeException {

		public BulkheadFullException() {
			super("Demasiadas llamadas concurrentes");
		}
	}
}
