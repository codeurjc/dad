package es.codeurjc.dad.balanceo.ejem4.autoscaling;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Algoritmo de autoescalado inspirado en el HorizontalPodAutoscaler de
 * Kubernetes. Java puro: sirve para entender (y probar) cómo decide un
 * autoescalador cuántas réplicas necesita.
 *
 * <pre>
 * deseadas = ceil( actuales × métricaActual / métricaObjetivo )
 * </pre>
 *
 * Con tres "frenos" para evitar oscilaciones (flapping):
 * <ul>
 * <li><b>Tolerancia</b>: si la métrica está a menos de un 10 % del objetivo, no
 * se hace nada.</li>
 * <li><b>Ventana de estabilización al bajar</b>: solo se reduce si TODAS las
 * recomendaciones recientes lo permiten (se toma el máximo de la ventana).
 * Subir rápido, bajar despacio.</li>
 * <li><b>Límite de crecimiento</b>: como mucho se duplica el número de réplicas
 * en cada paso.</li>
 * </ul>
 */
public class ReplicaCalculator {

	private final double target;
	private final int minReplicas;
	private final int maxReplicas;
	private final double tolerance;
	private final int scaleDownWindow;
	private final Deque<Integer> recentRecommendations = new ArrayDeque<>();

	/**
	 * @param target          valor objetivo de la métrica por réplica (p. ej. 60 = 60 % de CPU)
	 * @param scaleDownWindow número de evaluaciones que se recuerdan antes de bajar
	 */
	public ReplicaCalculator(double target, int minReplicas, int maxReplicas, double tolerance,
			int scaleDownWindow) {
		if (target <= 0 || minReplicas < 1 || maxReplicas < minReplicas) {
			throw new IllegalArgumentException("Configuración no válida");
		}
		this.target = target;
		this.minReplicas = minReplicas;
		this.maxReplicas = maxReplicas;
		this.tolerance = tolerance;
		this.scaleDownWindow = scaleDownWindow;
	}

	/**
	 * @param currentReplicas réplicas que hay ahora
	 * @param currentMetric   valor medio de la métrica en las réplicas actuales
	 * @return réplicas que debería haber
	 */
	public int desiredReplicas(int currentReplicas, double currentMetric) {
		double ratio = currentMetric / target;

		int raw;
		if (Math.abs(ratio - 1.0) <= tolerance) {
			raw = currentReplicas; // dentro de la tolerancia: no tocar
		} else {
			raw = (int) Math.ceil(currentReplicas * ratio);
		}

		// Límite de crecimiento por paso
		raw = Math.min(raw, Math.max(currentReplicas * 2, minReplicas));
		raw = clamp(raw);

		// Ventana de estabilización: para bajar usamos el máximo reciente
		recentRecommendations.addLast(raw);
		if (recentRecommendations.size() > scaleDownWindow) {
			recentRecommendations.removeFirst();
		}
		if (raw < currentReplicas) {
			int maxRecent = recentRecommendations.stream().mapToInt(Integer::intValue).max().orElse(raw);
			return clamp(Math.min(currentReplicas, maxRecent));
		}
		return raw;
	}

	private int clamp(int replicas) {
		return Math.max(minReplicas, Math.min(maxReplicas, replicas));
	}
}
