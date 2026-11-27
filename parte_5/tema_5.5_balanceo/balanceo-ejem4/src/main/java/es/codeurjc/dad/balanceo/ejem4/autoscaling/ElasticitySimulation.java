package es.codeurjc.dad.balanceo.ejem4.autoscaling;

import java.util.Locale;

/**
 * Simula un día de tráfico y cómo responde el autoescalador.
 *
 * Cada paso es un minuto. Cada réplica soporta 100 peticiones/s al 100 % de
 * CPU y el objetivo es mantenerla al 60 %. Las réplicas nuevas tardan 2 pasos
 * en estar listas (arranque de la JVM, readiness...).
 *
 * Ejecuta: mvn -q compile exec:java -Dexec.mainClass=... o desde el IDE.
 * Salida: CSV (minuto, peticiones/s, réplicas listas, CPU media)
 */
public class ElasticitySimulation {

	static final double CAPACITY_PER_REPLICA = 100;
	static final int STARTUP_STEPS = 2;

	public static void main(String[] args) {
		ReplicaCalculator hpa = new ReplicaCalculator(60, 2, 20, 0.1, 5);
		int ready = 2;
		int[] pending = new int[STARTUP_STEPS + 1];

		System.out.println("minuto,peticiones,replicas,cpu");
		for (int minute = 0; minute <= 120; minute++) {
			double load = load(minute);
			double cpu = Math.min(100, 100 * load / (ready * CAPACITY_PER_REPLICA));
			System.out.printf(Locale.ROOT, "%d,%.0f,%d,%.1f%n", minute, load, ready, cpu);

			// Las réplicas que terminan de arrancar pasan a estar listas
			ready += pending[0];
			System.arraycopy(pending, 1, pending, 0, STARTUP_STEPS);
			pending[STARTUP_STEPS] = 0;

			int planned = ready + sum(pending);
			int desired = hpa.desiredReplicas(planned, cpu * ready / planned);
			if (desired > planned) {
				pending[STARTUP_STEPS - 1] += desired - planned; // tardan en arrancar
			} else if (desired < planned) {
				ready -= Math.min(ready - 1, planned - desired); // apagar es inmediato
			}
		}
	}

	/** Tráfico: base de 150 pet/s, un pico gradual y una avalancha corta. */
	static double load(int minute) {
		double base = 150;
		double wave = 450 * Math.max(0, Math.sin(Math.PI * (minute - 10) / 80.0));
		double burst = (minute >= 70 && minute < 80) ? 600 : 0;
		return base + (minute >= 10 && minute <= 90 ? wave : 0) + burst;
	}

	private static int sum(int[] values) {
		int s = 0;
		for (int v : values) {
			s += v;
		}
		return s;
	}
}
