package es.codeurjc.dad.fund.ejem3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RaftTest {

	@ParameterizedTest
	@ValueSource(longs = { 1, 2, 3, 42, 2026 })
	void seEligeUnUnicoLider(long seed) {
		Cluster cluster = new Cluster(5, seed);
		cluster.runFor(2_000);

		long leaders = cluster.nodes().stream().filter(n -> n.state() == Node.State.LEADER).count();
		assertEquals(1, leaders);
	}

	@ParameterizedTest
	@ValueSource(longs = { 1, 2, 3, 42, 2026 })
	void nuncaHayDosLideresEnElMismoMandato(long seed) {
		Cluster cluster = new Cluster(5, seed);
		cluster.runFor(1_000);
		cluster.partition(Set.of(0, 1));
		cluster.runFor(2_000);
		cluster.heal();
		cluster.runFor(2_000);

		cluster.leadersByTerm().forEach((term, leaders) -> assertEquals(1, leaders.size(), "mandato " + term));
	}

	@ParameterizedTest
	@ValueSource(longs = { 1, 2, 3, 42, 2026 })
	void unaOrdenSeComprometeYLlegaATodos(long seed) {
		Cluster cluster = new Cluster(5, seed);
		cluster.runFor(1_000);

		cluster.submit("x=1");
		cluster.runFor(500);

		cluster.nodes().forEach(n -> assertEquals(List.of("x=1"), n.committed(), "nodo " + n.id()));
	}

	@ParameterizedTest
	@ValueSource(longs = { 1, 2, 3, 42, 2026 })
	void unLiderEnMinoriaNoPuedeComprometerYLaMayoriaSigue(long seed) {
		Cluster cluster = new Cluster(5, seed);
		cluster.runFor(1_000);
		Node oldLeader = cluster.leader().orElseThrow();
		int other = (oldLeader.id() + 1) % 5;

		cluster.partition(Set.of(oldLeader.id(), other));
		oldLeader.submit("x=minoria");
		cluster.runFor(1_500);

		assertEquals(0, oldLeader.commitIndex(), "sin mayoría no se compromete nada");
		Node newLeader = cluster.leader().orElseThrow();
		assertNotEquals(oldLeader.id(), newLeader.id());
		assertTrue(newLeader.term() > oldLeader.term());

		cluster.submit("x=mayoria");
		cluster.runFor(500);
		assertEquals(List.of("x=mayoria"), newLeader.committed());

		// Al recuperar la red, el antiguo líder se entera, deja de serlo y
		// su entrada no comprometida se sustituye por la de la mayoría
		cluster.heal();
		cluster.runFor(1_000);
		assertFalse(oldLeader.state() == Node.State.LEADER);
		assertEquals(List.of("x=mayoria"), oldLeader.committed());
	}
}
