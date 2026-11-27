package es.codeurjc.dad.micro.ejem3.pedidos.resilience;

import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Reintentos con espera exponencial y jitter.
 *
 * <ul>
 * <li>Solo se reintentan los errores TRANSITORIOS (timeouts, 503...). Un 404 o
 * un 400 van a fallar igual la segunda vez.</li>
 * <li>La espera crece (100 ms, 200 ms, 400 ms...) para no machacar a un
 * servicio que ya tiene problemas.</li>
 * <li>El jitter (azar) evita que todos los clientes reintenten a la vez.</li>
 * <li>Cuidado: reintentar operaciones que no son idempotentes (POST de un
 * pago) puede duplicarlas.</li>
 * </ul>
 */
public class Retry {

	private final int maxAttempts;
	private final Duration initialBackoff;
	private final Predicate<RuntimeException> retryable;
	private final Sleeper sleeper;

	@FunctionalInterface
	public interface Sleeper {

		void sleep(Duration duration) throws InterruptedException;
	}

	public Retry(int maxAttempts, Duration initialBackoff, Predicate<RuntimeException> retryable, Sleeper sleeper) {
		this.maxAttempts = maxAttempts;
		this.initialBackoff = initialBackoff;
		this.retryable = retryable;
		this.sleeper = sleeper;
	}

	public Retry(int maxAttempts, Duration initialBackoff, Predicate<RuntimeException> retryable) {
		this(maxAttempts, initialBackoff, retryable, d -> Thread.sleep(d.toMillis()));
	}

	public <T> T call(Supplier<T> action) {
		long backoff = initialBackoff.toMillis();
		for (int attempt = 1;; attempt++) {
			try {
				return action.get();
			} catch (RuntimeException e) {
				if (attempt >= maxAttempts || !retryable.test(e)) {
					throw e;
				}
				long jitter = backoff > 0 ? ThreadLocalRandom.current().nextLong(backoff / 2 + 1) : 0;
				try {
					sleeper.sleep(Duration.ofMillis(backoff + jitter));
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw e;
				}
				backoff *= 2;
			}
		}
	}
}
