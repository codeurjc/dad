package es.codeurjc.dad.fund.ejer1;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Red que entrega todos los mensajes, pero en un orden aleatorio distinto
 * para cada destinatario (reproducible con una semilla).
 */
public class UnreliableNetwork {

	private record Delivery(Participant to, ChatMessage message) {
	}

	private final List<Participant> participants;
	private final List<Delivery> inFlight = new ArrayList<>();
	private final Random random;

	public UnreliableNetwork(List<Participant> participants, long seed) {
		this.participants = List.copyOf(participants);
		this.random = new Random(seed);
	}

	public void broadcast(ChatMessage m) {
		for (Participant p : participants) {
			if (p.id() != m.sender()) {
				inFlight.add(new Delivery(p, m));
			}
		}
	}

	/** Entrega algunos mensajes en desorden (o todos, si fraction = 1). */
	public void deliver(double fraction) {
		Collections.shuffle(inFlight, random);
		int n = (int) Math.ceil(inFlight.size() * fraction);
		List<Delivery> now = new ArrayList<>(inFlight.subList(0, n));
		inFlight.subList(0, n).clear();
		now.forEach(d -> d.to().receive(d.message()));
	}
}
