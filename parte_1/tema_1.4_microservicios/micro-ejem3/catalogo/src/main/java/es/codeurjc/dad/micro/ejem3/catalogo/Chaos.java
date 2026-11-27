package es.codeurjc.dad.micro.ejem3.catalogo;

import java.util.concurrent.ThreadLocalRandom;

import org.springframework.stereotype.Component;

/**
 * Inyección de fallos (chaos engineering, en pequeñito): permite hacer que el
 * servicio tarde o falle a propósito para ver cómo reaccionan sus clientes.
 */
@Component
public class Chaos {

	public record Settings(long latencyMs, double failureRate) {
	}

	private volatile Settings settings = new Settings(0, 0);

	public void apply() throws InterruptedException {
		Settings s = settings;
		if (s.latencyMs() > 0) {
			Thread.sleep(s.latencyMs());
		}
		if (ThreadLocalRandom.current().nextDouble() < s.failureRate()) {
			throw new ChaosException();
		}
	}

	public Settings settings() {
		return settings;
	}

	public void update(Settings settings) {
		this.settings = settings;
	}

	public static class ChaosException extends RuntimeException {

		public ChaosException() {
			super("Fallo inyectado");
		}
	}
}
