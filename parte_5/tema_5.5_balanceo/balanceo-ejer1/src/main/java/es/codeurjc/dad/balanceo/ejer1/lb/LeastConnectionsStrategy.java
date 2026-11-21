package es.codeurjc.dad.balanceo.ejer1.lb;

import java.util.Comparator;
import java.util.List;

/**
 * Al que menos peticiones tiene en curso. Útil cuando las peticiones tienen
 * duraciones muy distintas (round robin no lo tiene en cuenta).
 */
public class LeastConnectionsStrategy implements Strategy {

	@Override
	public Backend choose(List<Backend> healthy, String clientKey) {
		return healthy.stream()
				.min(Comparator.comparingDouble((Backend b) -> (double) b.activeRequests() / b.weight()))
				.orElseThrow();
	}
}
