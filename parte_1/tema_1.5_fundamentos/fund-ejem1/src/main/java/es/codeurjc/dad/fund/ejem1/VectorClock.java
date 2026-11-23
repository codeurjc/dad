package es.codeurjc.dad.fund.ejem1;

import java.util.Arrays;

/**
 * Reloj vectorial: cada proceso lleva un contador POR CADA proceso del sistema.
 *
 * V(a) &lt; V(b) (todas las componentes ≤ y alguna &lt;) si y solo si a → b.
 * Si ninguno es menor que el otro, los eventos son CONCURRENTES: ninguno pudo
 * influir en el otro. Es lo que usan, por ejemplo, las bases de datos sin
 * líder para detectar escrituras en conflicto.
 *
 * Inmutable: cada operación devuelve un reloj nuevo.
 */
public final class VectorClock {

	public enum Order {
		BEFORE, AFTER, EQUAL, CONCURRENT
	}

	private final long[] counters;

	private VectorClock(long[] counters) {
		this.counters = counters;
	}

	public static VectorClock zero(int processes) {
		return new VectorClock(new long[processes]);
	}

	/** Evento local (o envío) en el proceso i. */
	public VectorClock tick(int i) {
		long[] c = counters.clone();
		c[i]++;
		return new VectorClock(c);
	}

	/** Recepción en el proceso i de un mensaje con reloj "remote". */
	public VectorClock merge(int i, VectorClock remote) {
		long[] c = new long[counters.length];
		for (int k = 0; k < c.length; k++) {
			c[k] = Math.max(counters[k], remote.counters[k]);
		}
		c[i]++;
		return new VectorClock(c);
	}

	public Order compareTo(VectorClock other) {
		boolean less = false;
		boolean greater = false;
		for (int k = 0; k < counters.length; k++) {
			if (counters[k] < other.counters[k]) {
				less = true;
			} else if (counters[k] > other.counters[k]) {
				greater = true;
			}
		}
		if (less && greater) {
			return Order.CONCURRENT;
		}
		if (less) {
			return Order.BEFORE;
		}
		if (greater) {
			return Order.AFTER;
		}
		return Order.EQUAL;
	}

	public long get(int i) {
		return counters[i];
	}

	public int size() {
		return counters.length;
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof VectorClock v && Arrays.equals(counters, v.counters);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(counters);
	}

	@Override
	public String toString() {
		return Arrays.toString(counters);
	}
}
