package es.codeurjc.dad.fund.ejem3;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.Set;

import es.codeurjc.dad.fund.ejem3.Messages.Message;

/**
 * Simulación determinista de un clúster Raft: el tiempo avanza en pasos de
 * 1 ms y la red entrega cada mensaje con un retardo aleatorio (pero
 * reproducible gracias a la semilla). Se pueden provocar particiones de red.
 */
public class Cluster {

	private record InFlight(long deliverAt, long seq, int from, int to, Message message) {
	}

	private final List<Node> nodes = new ArrayList<>();
	private final Random random;
	private final PriorityQueue<InFlight> network = new PriorityQueue<>(
			(a, b) -> a.deliverAt != b.deliverAt ? Long.compare(a.deliverAt, b.deliverAt) : Long.compare(a.seq, b.seq));
	private final Map<Long, Set<Integer>> leadersByTerm = new HashMap<>();
	private final List<String> events = new ArrayList<>();
	private Set<Integer> partitionA = Set.of();
	private long now;
	private long seq;

	public Cluster(int size, long seed) {
		this.random = new Random(seed);
		for (int i = 0; i < size; i++) {
			nodes.add(new Node(i, size, this, new Random(random.nextLong())));
		}
	}

	// ------------------------------------------------------------ red

	void send(int from, int to, Message m) {
		if (canTalk(from, to)) {
			network.add(new InFlight(now + 5 + random.nextInt(10), seq++, from, to, m));
		}
	}

	private boolean canTalk(int a, int b) {
		return partitionA.isEmpty() || partitionA.contains(a) == partitionA.contains(b);
	}

	/** Parte la red en dos: los nodos indicados y el resto. */
	public void partition(Set<Integer> side) {
		partitionA = Set.copyOf(side);
		events.add(now + " ms: partición " + side + " | resto");
	}

	public void heal() {
		partitionA = Set.of();
		events.add(now + " ms: la red se recupera");
	}

	// ------------------------------------------------------------ tiempo

	public void runFor(long millis) {
		long end = now + millis;
		while (now < end) {
			now++;
			while (!network.isEmpty() && network.peek().deliverAt() <= now) {
				InFlight f = network.poll();
				if (canTalk(f.from(), f.to())) { // la partición puede haber empezado por el camino
					nodes.get(f.to()).receive(f.from(), f.message(), now);
				}
			}
			for (Node n : nodes) {
				n.tick(now);
			}
		}
	}

	void leaderElected(int id, long term) {
		leadersByTerm.computeIfAbsent(term, t -> new HashSet<>()).add(id);
		events.add(now + " ms: el nodo " + id + " es LÍDER del mandato " + term);
	}

	// ------------------------------------------------------------ consultas

	/** El líder del mandato más alto entre los nodos que se creen líderes. */
	public Optional<Node> leader() {
		return nodes.stream().filter(n -> n.state() == Node.State.LEADER)
				.max((a, b) -> Long.compare(a.term(), b.term()));
	}

	public int submit(String command) {
		return leader().orElseThrow(() -> new IllegalStateException("No hay líder")).submit(command);
	}

	public Node node(int id) {
		return nodes.get(id);
	}

	public List<Node> nodes() {
		return List.copyOf(nodes);
	}

	public Map<Long, Set<Integer>> leadersByTerm() {
		return Map.copyOf(leadersByTerm);
	}

	public List<String> events() {
		return List.copyOf(events);
	}

	public long now() {
		return now;
	}
}
