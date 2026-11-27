package es.codeurjc.dad.fund.ejem2;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.Optional;

/**
 * Almacén replicado SIN LÍDER (al estilo de Dynamo, Cassandra o Riak).
 *
 * <ul>
 * <li>N réplicas guardan cada dato.</li>
 * <li>Una escritura se confirma cuando W réplicas la han guardado. Al resto
 * le llega más tarde (replicación asíncrona: {@link #propagate()}).</li>
 * <li>Una lectura pregunta a R réplicas y se queda con la versión más alta.
 * Si alguna de las consultadas estaba desactualizada, se le corrige
 * (read repair).</li>
 * </ul>
 *
 * Si W + R &gt; N, el conjunto de réplicas leídas y el de escritas siempre se
 * solapan en al menos una: la lectura ve la última escritura confirmada.
 * Si W + R ≤ N, se pueden leer datos antiguos.
 *
 * Simulación determinista: las escrituras van a las primeras réplicas vivas y
 * las lecturas van rotando, para que se vea el efecto.
 */
public class QuorumStore {

	private record Pending(Replica replica, String key, Versioned value) {
	}

	private final List<Replica> replicas;
	private final int w;
	private final int r;
	private final Deque<Pending> pending = new ArrayDeque<>();
	private long clock;
	private int readOffset;

	public QuorumStore(List<Replica> replicas, int w, int r) {
		if (w < 1 || r < 1 || w > replicas.size() || r > replicas.size()) {
			throw new IllegalArgumentException("W y R deben estar entre 1 y N");
		}
		this.replicas = List.copyOf(replicas);
		this.w = w;
		this.r = r;
	}

	public void put(String key, String value) {
		List<Replica> alive = alive(0);
		if (alive.size() < w) {
			throw new QuorumException("escribir", w, alive.size());
		}
		Versioned v = new Versioned(value, ++clock);
		for (int i = 0; i < alive.size(); i++) {
			if (i < w) {
				alive.get(i).write(key, v); // confirman la escritura
			} else {
				pending.add(new Pending(alive.get(i), key, v)); // les llegará más tarde
			}
		}
		// Las réplicas caídas también la recibirán cuando vuelvan (hinted handoff)
		replicas.stream().filter(rep -> !rep.isUp()).forEach(rep -> pending.add(new Pending(rep, key, v)));
	}

	public Optional<String> get(String key) {
		List<Replica> alive = alive(readOffset++);
		if (alive.size() < r) {
			throw new QuorumException("leer", r, alive.size());
		}
		List<Replica> asked = alive.subList(0, r);
		Optional<Versioned> newest = asked.stream()
				.map(rep -> rep.read(key))
				.flatMap(Optional::stream)
				.max(Comparator.comparingLong(Versioned::version));
		// Read repair: actualizar a las consultadas que estaban atrasadas
		newest.ifPresent(v -> asked.forEach(rep -> rep.write(key, v)));
		return newest.map(Versioned::value);
	}

	/** Entrega las escrituras pendientes a las réplicas que estén vivas. */
	public void propagate() {
		int n = pending.size();
		for (int i = 0; i < n; i++) {
			Pending p = pending.poll();
			if (p.replica().isUp()) {
				p.replica().write(p.key(), p.value());
			} else {
				pending.add(p);
			}
		}
	}

	private List<Replica> alive(int offset) {
		List<Replica> result = new ArrayList<>();
		for (int i = 0; i < replicas.size(); i++) {
			Replica rep = replicas.get((offset + i) % replicas.size());
			if (rep.isUp()) {
				result.add(rep);
			}
		}
		return result;
	}
}
