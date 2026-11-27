package es.codeurjc.dad.balanceo.ejer1.lb;

import java.util.List;
import java.util.Optional;

/**
 * El balanceador: combina el algoritmo de balanceo, la comprobación de salud
 * y las sticky sessions. Java puro: no sabe nada de HTTP.
 */
public class LoadBalancer {

	/** Resultado de elegir servidor: si hay que (re)escribir la cookie de afinidad. */
	public record Selection(Backend backend, boolean setStickyCookie) {
	}

	private final List<Backend> backends;
	private final Strategy strategy;
	private final boolean sticky;

	public LoadBalancer(List<Backend> backends, Strategy strategy, boolean sticky) {
		if (backends.isEmpty()) {
			throw new IllegalArgumentException("Hace falta al menos un servidor");
		}
		this.backends = List.copyOf(backends);
		this.strategy = strategy;
		this.sticky = sticky;
	}

	/**
	 * @param clientKey    IP del cliente
	 * @param stickyCookie valor de la cookie de afinidad, si la trae
	 */
	public Selection choose(String clientKey, Optional<String> stickyCookie) {
		List<Backend> healthy = healthyBackends();
		if (healthy.isEmpty()) {
			throw new NoHealthyBackendException();
		}
		if (sticky && stickyCookie.isPresent()) {
			Optional<Backend> pinned = healthy.stream().filter(b -> b.id().equals(stickyCookie.get())).findFirst();
			if (pinned.isPresent()) {
				return new Selection(pinned.get(), false);
			}
			// El servidor de la cookie no existe o está caído: "redispatch"
		}
		return new Selection(strategy.choose(healthy, clientKey), sticky);
	}

	public List<Backend> healthyBackends() {
		return backends.stream().filter(Backend::isHealthy).toList();
	}

	public List<Backend> backends() {
		return backends;
	}
}
