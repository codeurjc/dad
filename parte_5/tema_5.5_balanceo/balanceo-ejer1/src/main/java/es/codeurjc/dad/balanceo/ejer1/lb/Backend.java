package es.codeurjc.dad.balanceo.ejer1.lb;

import java.net.URI;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Un servidor al que el balanceador puede enviar peticiones.
 */
public class Backend {

	private final String id;
	private final URI uri;
	private final int weight;
	private final AtomicInteger activeRequests = new AtomicInteger();
	private volatile boolean healthy = true;

	public Backend(String id, URI uri, int weight) {
		if (weight < 1) {
			throw new IllegalArgumentException("El peso debe ser al menos 1");
		}
		this.id = Objects.requireNonNull(id);
		this.uri = Objects.requireNonNull(uri);
		this.weight = weight;
	}

	public Backend(String id, String uri) {
		this(id, URI.create(uri), 1);
	}

	public void requestStarted() {
		activeRequests.incrementAndGet();
	}

	public void requestFinished() {
		activeRequests.decrementAndGet();
	}

	public void markHealthy(boolean healthy) {
		this.healthy = healthy;
	}

	public String id() {
		return id;
	}

	public URI uri() {
		return uri;
	}

	public int weight() {
		return weight;
	}

	public int activeRequests() {
		return activeRequests.get();
	}

	public boolean isHealthy() {
		return healthy;
	}

	@Override
	public String toString() {
		return id + "(" + uri + (healthy ? "" : ", CAÍDO") + ")";
	}
}
