package es.codeurjc.dad.balanceo.ejer1.lb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class StrategiesTest {

	private final Backend s1 = new Backend("s1", "http://h1");
	private final Backend s2 = new Backend("s2", "http://h2");
	private final Backend s3 = new Backend("s3", "http://h3");

	private static List<String> pick(Strategy strategy, List<Backend> backends, int n) {
		List<String> ids = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			ids.add(strategy.choose(backends, "10.0.0." + i).id());
		}
		return ids;
	}

	@Test
	void roundRobinVaPorTurnos() {
		assertEquals(List.of("s1", "s2", "s3", "s1", "s2", "s3"),
				pick(new RoundRobinStrategy(), List.of(s1, s2, s3), 6));
	}

	@Test
	void roundRobinPonderadoRespetaLosPesosIntercalando() {
		Backend heavy = new Backend("A", URI.create("http://a"), 3);
		Backend light = new Backend("B", URI.create("http://b"), 1);

		assertEquals(List.of("A", "A", "B", "A", "A", "A", "B", "A"),
				pick(new WeightedRoundRobinStrategy(), List.of(heavy, light), 8));
	}

	@Test
	void menosConexionesEligeAlMenosOcupado() {
		s1.requestStarted();
		s1.requestStarted();
		s3.requestStarted();
		assertEquals("s2", new LeastConnectionsStrategy().choose(List.of(s1, s2, s3), "x").id());
	}

	@Test
	void hashConsistenteDaSiempreElMismoServidorAlMismoCliente() {
		ConsistentHashStrategy hash = new ConsistentHashStrategy();
		String first = hash.choose(List.of(s1, s2, s3), "192.168.1.20").id();
		for (int i = 0; i < 10; i++) {
			assertEquals(first, hash.choose(List.of(s1, s2, s3), "192.168.1.20").id());
		}
	}

	@Test
	void alQuitarUnServidorSoloSeMuevenSusClientes() {
		ConsistentHashStrategy hash = new ConsistentHashStrategy();
		Map<String, String> before = new HashMap<>();
		for (int i = 0; i < 1000; i++) {
			before.put("cliente-" + i, hash.choose(List.of(s1, s2, s3), "cliente-" + i).id());
		}
		int moved = 0;
		for (int i = 0; i < 1000; i++) {
			String now = hash.choose(List.of(s1, s2), "cliente-" + i).id();
			String old = before.get("cliente-" + i);
			if (!old.equals("s3") && !old.equals(now)) {
				moved++;
			}
		}
		// Con hash % N cambiarían de servidor ~2/3 de los clientes; aquí, ninguno de s1 y s2
		assertEquals(0, moved);
		assertTrue(before.containsValue("s3"));
	}
}
