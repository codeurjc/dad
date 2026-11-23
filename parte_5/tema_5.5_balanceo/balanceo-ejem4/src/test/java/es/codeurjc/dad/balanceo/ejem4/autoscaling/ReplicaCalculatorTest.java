package es.codeurjc.dad.balanceo.ejem4.autoscaling;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ReplicaCalculatorTest {

	@Test
	void escalaProporcionalmenteALaMetrica() {
		ReplicaCalculator hpa = new ReplicaCalculator(50, 1, 10, 0.1, 1);
		// 4 réplicas al 75 % con objetivo 50 % -> 4 * 1.5 = 6
		assertEquals(6, hpa.desiredReplicas(4, 75));
	}

	@Test
	void dentroDeLaToleranciaNoHaceNada() {
		ReplicaCalculator hpa = new ReplicaCalculator(50, 1, 10, 0.1, 1);
		assertEquals(4, hpa.desiredReplicas(4, 54));
	}

	@Test
	void respetaElMinimoYElMaximo() {
		ReplicaCalculator hpa = new ReplicaCalculator(50, 2, 5, 0.1, 1);
		assertEquals(5, hpa.desiredReplicas(4, 100));
		assertEquals(2, hpa.desiredReplicas(3, 1));
	}

	@Test
	void comoMuchoDuplicaEnCadaPaso() {
		ReplicaCalculator hpa = new ReplicaCalculator(10, 1, 100, 0.1, 1);
		assertEquals(4, hpa.desiredReplicas(2, 100));
	}

	@Test
	void bajaDespacioPorLaVentanaDeEstabilizacion() {
		ReplicaCalculator hpa = new ReplicaCalculator(50, 1, 10, 0.1, 3);
		assertEquals(8, hpa.desiredReplicas(4, 100)); // pico
		// la carga cae de golpe, pero recordamos la recomendación de 8
		assertEquals(8, hpa.desiredReplicas(8, 10));
		assertEquals(8, hpa.desiredReplicas(8, 10));
		// la recomendación alta sale de la ventana: ahora sí baja
		assertEquals(2, hpa.desiredReplicas(8, 10));
	}
}
