package es.codeurjc.dad.fund.ejer1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class CausalChatTest {

	@Test
	void laRespuestaNuncaSeVeAntesQueLaPregunta() {
		for (long seed = 0; seed < 200; seed++) {
			Participant ana = new Participant(0, "Ana", 3);
			Participant luis = new Participant(1, "Luis", 3);
			Participant eva = new Participant(2, "Eva", 3);
			UnreliableNetwork net = new UnreliableNetwork(List.of(ana, luis, eva), seed);

			ChatMessage question = ana.write("¿Quedamos?");
			net.broadcast(question);
			luis.receive(question); // Luis la lee (Eva todavía no)
			net.broadcast(luis.write("¡Vale!"));
			net.deliver(1);

			List<String> evaSees = eva.conversation();
			assertEquals(List.of("0: ¿Quedamos?", "1: ¡Vale!"), evaSees, "semilla " + seed);
		}
	}

	@Test
	void todosLosMensajesAcabanEntregandose() {
		Participant a = new Participant(0, "A", 3);
		Participant b = new Participant(1, "B", 3);
		Participant c = new Participant(2, "C", 3);
		UnreliableNetwork net = new UnreliableNetwork(List.of(a, b, c), 99);

		for (int i = 0; i < 10; i++) {
			net.broadcast(a.write("a" + i));
			net.broadcast(b.write("b" + i));
			net.deliver(0.3);
			net.broadcast(c.write("c" + i));
		}
		net.deliver(1);

		for (Participant p : List.of(a, b, c)) {
			assertEquals(30, p.conversation().size(), p.name());
			assertEquals(0, p.pending());
		}
	}

	@Test
	void losMensajesDeUnMismoEmisorSeVenEnOrden() {
		Participant a = new Participant(0, "A", 2);
		Participant b = new Participant(1, "B", 2);
		ChatMessage m1 = a.write("1");
		ChatMessage m2 = a.write("2");
		ChatMessage m3 = a.write("3");

		b.receive(m3);
		b.receive(m1);
		assertEquals(List.of("0: 1"), b.conversation(), "m3 espera a m2");
		b.receive(m2);
		assertEquals(List.of("0: 1", "0: 2", "0: 3"), b.conversation());
		assertTrue(b.pending() == 0);
	}
}
