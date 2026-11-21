package es.codeurjc.dad.balanceo.ejer1.lb;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Round robin ponderado "suave" (el algoritmo de nginx): un servidor con peso 3
 * recibe 3 de cada 4 peticiones frente a uno de peso 1, pero intercaladas
 * (A A B A, no A A A B), para no concentrar ráfagas en el mismo servidor.
 */
public class WeightedRoundRobinStrategy implements Strategy {

	private final Map<String, Integer> currentWeights = new HashMap<>();

	@Override
	public synchronized Backend choose(List<Backend> healthy, String clientKey) {
		int total = 0;
		Backend best = null;
		for (Backend b : healthy) {
			int current = currentWeights.getOrDefault(b.id(), 0) + b.weight();
			currentWeights.put(b.id(), current);
			total += b.weight();
			if (best == null || current > currentWeights.get(best.id())) {
				best = b;
			}
		}
		currentWeights.put(best.id(), currentWeights.get(best.id()) - total);
		return best;
	}
}
