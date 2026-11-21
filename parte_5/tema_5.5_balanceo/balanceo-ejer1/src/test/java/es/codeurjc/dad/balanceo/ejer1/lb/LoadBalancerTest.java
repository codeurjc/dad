package es.codeurjc.dad.balanceo.ejer1.lb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import es.codeurjc.dad.balanceo.ejer1.lb.LoadBalancer.Selection;

class LoadBalancerTest {

	private final Backend s1 = new Backend("s1", "http://h1");
	private final Backend s2 = new Backend("s2", "http://h2");

	@Test
	void sinCookieSeEligeServidorYSePideFijarLaCookie() {
		LoadBalancer lb = new LoadBalancer(List.of(s1, s2), new RoundRobinStrategy(), true);

		Selection selection = lb.choose("ip", Optional.empty());

		assertTrue(selection.setStickyCookie());
	}

	@Test
	void conCookieSeVaSiempreAlMismoServidor() {
		LoadBalancer lb = new LoadBalancer(List.of(s1, s2), new RoundRobinStrategy(), true);

		for (int i = 0; i < 5; i++) {
			Selection selection = lb.choose("ip", Optional.of("s2"));
			assertEquals("s2", selection.backend().id());
			assertFalse(selection.setStickyCookie());
		}
	}

	@Test
	void siElServidorDeLaCookieCaeSeRedirigeAOtro() {
		LoadBalancer lb = new LoadBalancer(List.of(s1, s2), new RoundRobinStrategy(), true);
		s2.markHealthy(false);

		Selection selection = lb.choose("ip", Optional.of("s2"));

		assertEquals("s1", selection.backend().id());
		assertTrue(selection.setStickyCookie(), "hay que reescribir la cookie");
	}

	@Test
	void losServidoresCaidosNoRecibenPeticiones() {
		LoadBalancer lb = new LoadBalancer(List.of(s1, s2), new RoundRobinStrategy(), false);
		s1.markHealthy(false);
		for (int i = 0; i < 4; i++) {
			assertEquals("s2", lb.choose("ip", Optional.empty()).backend().id());
		}
	}

	@Test
	void sinServidoresSanosSeLanzaExcepcion() {
		LoadBalancer lb = new LoadBalancer(List.of(s1), new RoundRobinStrategy(), false);
		s1.markHealthy(false);
		assertThrows(NoHealthyBackendException.class, () -> lb.choose("ip", Optional.empty()));
	}
}
