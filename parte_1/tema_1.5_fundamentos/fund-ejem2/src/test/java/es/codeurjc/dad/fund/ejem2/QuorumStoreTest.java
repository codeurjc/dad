package es.codeurjc.dad.fund.ejem2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class QuorumStoreTest {

	private final List<Replica> rs = List.of(new Replica("r1"), new Replica("r2"), new Replica("r3"));

	@Test
	void conQuorumSolapadoSiempreSeLeeLaUltimaEscritura() {
		QuorumStore store = new QuorumStore(rs, 2, 2);
		store.put("x", "a");
		store.propagate();
		store.put("x", "b"); // aún no ha llegado a r3

		for (int i = 0; i < 6; i++) {
			assertEquals("b", store.get("x").orElseThrow());
		}
	}

	@Test
	void sinSolapamientoSePuedeLeerUnValorAntiguo() {
		QuorumStore store = new QuorumStore(rs, 1, 1);
		store.put("x", "a");
		store.propagate();
		store.put("x", "b"); // solo en r1

		List<String> reads = List.of(store.get("x").orElseThrow(), store.get("x").orElseThrow(),
				store.get("x").orElseThrow());
		assertTrue(reads.contains("a"), "alguna lectura devuelve el valor antiguo: " + reads);
	}

	@Test
	void elReadRepairActualizaLasReplicasConsultadas() {
		QuorumStore store = new QuorumStore(rs, 1, 3);
		store.put("x", "a"); // solo en r1

		store.get("x");

		assertEquals("a", rs.get(2).peek("x").orElseThrow().value());
	}

	@Test
	void sinQuorumNoSePuedeEscribirNiLeer() {
		QuorumStore store = new QuorumStore(rs, 2, 2);
		rs.get(0).crash();
		rs.get(1).crash();

		assertThrows(QuorumException.class, () -> store.put("x", "a"));
		assertThrows(QuorumException.class, () -> store.get("x"));
	}

	@Test
	void unaReplicaCaidaRecibeLasEscriturasAlVolver() {
		QuorumStore store = new QuorumStore(rs, 2, 2);
		rs.get(2).crash();
		store.put("x", "a");

		rs.get(2).recover();
		store.propagate();

		assertEquals("a", rs.get(2).peek("x").orElseThrow().value());
	}
}
