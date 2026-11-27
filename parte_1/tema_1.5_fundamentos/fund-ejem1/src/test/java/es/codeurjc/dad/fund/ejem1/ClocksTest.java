package es.codeurjc.dad.fund.ejem1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import es.codeurjc.dad.fund.ejem1.VectorClock.Order;

class ClocksTest {

	@Test
	void lamportRespetaLaRelacionOcurreAntes() {
		LamportClock a = new LamportClock();
		LamportClock b = new LamportClock();
		b.tick();
		b.tick();
		b.tick(); // B va "adelantado"

		long sent = a.send(); // 1
		long received = b.receive(sent); // max(3, 1) + 1

		assertEquals(1, sent);
		assertEquals(4, received);
		assertTrue(sent < received);
	}

	@Test
	void elRelojVectorialDetectaCausalidad() {
		VectorClock a = VectorClock.zero(2).tick(0); // [1,0]
		VectorClock b = VectorClock.zero(2).merge(1, a); // [1,1]

		assertEquals(Order.BEFORE, a.compareTo(b));
		assertEquals(Order.AFTER, b.compareTo(a));
	}

	@Test
	void elRelojVectorialDetectaConcurrencia() {
		VectorClock a = VectorClock.zero(2).tick(0); // [1,0]
		VectorClock b = VectorClock.zero(2).tick(1); // [0,1]

		assertEquals(Order.CONCURRENT, a.compareTo(b));
	}

	@Test
	void lamportNoDistingueConcurrenciaDeCausalidad() {
		LamportClock a = new LamportClock();
		LamportClock b = new LamportClock();
		long ea = a.tick(); // 1
		b.tick();
		long eb = b.tick(); // 2, independiente de ea

		assertTrue(ea < eb, "Lamport los ordena...");
		VectorClock va = VectorClock.zero(2).tick(0);
		VectorClock vb = VectorClock.zero(2).tick(1).tick(1);
		assertEquals(Order.CONCURRENT, va.compareTo(vb), "...pero eran concurrentes");
	}
}
