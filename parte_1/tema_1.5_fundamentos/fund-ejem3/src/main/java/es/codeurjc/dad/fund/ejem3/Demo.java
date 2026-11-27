package es.codeurjc.dad.fund.ejem3;

import java.util.Set;

/**
 * Un clúster de 5 nodos: elección, replicación, partición de red y recuperación.
 *
 * Ejecuta: mvn -q compile exec:java -Dexec.mainClass=es.codeurjc.dad.fund.ejem3.Demo
 */
public class Demo {

	public static void main(String[] args) {
		Cluster cluster = new Cluster(5, 42);
		cluster.runFor(1_000);
		Node leader = cluster.leader().orElseThrow();

		cluster.submit("x=1");
		cluster.runFor(200);
		print(cluster, "Tras escribir x=1");

		// El líder queda en minoría con otro nodo
		int other = (leader.id() + 1) % 5;
		cluster.partition(Set.of(leader.id(), other));
		leader.submit("x=2 (minoría)");
		cluster.runFor(1_000);
		cluster.submit("x=3 (mayoría)");
		cluster.runFor(300);
		print(cluster, "Durante la partición");

		cluster.heal();
		cluster.runFor(1_000);
		print(cluster, "Tras recuperar la red");

		System.out.println("Eventos:");
		cluster.events().forEach(e -> System.out.println("  " + e));
	}

	static void print(Cluster cluster, String title) {
		System.out.println(title + ":");
		for (Node n : cluster.nodes()) {
			System.out.printf("  nodo %d  %-9s mandato %d  log %s  comprometido %s%n", n.id(), n.state(), n.term(),
					n.log().stream().map(e -> e.command() + "@" + e.term()).toList(), n.committed());
		}
		System.out.println();
	}
}
