package es.codeurjc.dad.fund.ejer1;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Participante de un chat de grupo con ENTREGA CAUSAL.
 *
 * La red puede desordenar los mensajes. Si Ana pregunta y Luis responde
 * después de leer la pregunta, nadie debe ver la respuesta antes que la
 * pregunta. Los mensajes concurrentes (que nadie había leído al escribir el
 * otro) pueden verse en distinto orden en cada participante.
 *
 * Regla de entrega de un mensaje m enviado por j, en el participante i:
 * <ul>
 * <li>m.clock[j] == local[j] + 1 → es el siguiente mensaje de j que me falta, y</li>
 * <li>m.clock[k] ≤ local[k] para todo k ≠ j → ya he entregado todo lo que j
 * había visto al escribirlo.</li>
 * </ul>
 * Si no se cumple, el mensaje espera en un búfer.
 */
public class Participant {

	private final int id;
	private final String name;
	private VectorClock clock;
	private final List<ChatMessage> buffer = new ArrayList<>();
	private final List<ChatMessage> delivered = new ArrayList<>();

	public Participant(int id, String name, int groupSize) {
		this.id = id;
		this.name = name;
		this.clock = VectorClock.zero(groupSize);
	}

	/** Escribe un mensaje: se entrega a sí mismo y devuelve lo que hay que difundir. */
	public ChatMessage write(String text) {
		clock = clock.tick(id);
		ChatMessage m = new ChatMessage(id, text, clock);
		delivered.add(m);
		return m;
	}

	/** Llega un mensaje de la red (en cualquier orden). */
	public void receive(ChatMessage m) {
		if (m.sender() == id) {
			return;
		}
		buffer.add(m);
		boolean progress = true;
		while (progress) {
			progress = false;
			for (Iterator<ChatMessage> it = buffer.iterator(); it.hasNext();) {
				ChatMessage candidate = it.next();
				if (deliverable(candidate)) {
					it.remove();
					deliver(candidate);
					progress = true;
				}
			}
		}
	}

	private boolean deliverable(ChatMessage m) {
		int j = m.sender();
		if (m.clock().get(j) != clock.get(j) + 1) {
			return false;
		}
		for (int k = 0; k < clock.size(); k++) {
			if (k != j && m.clock().get(k) > clock.get(k)) {
				return false;
			}
		}
		return true;
	}

	private void deliver(ChatMessage m) {
		// Al entregar, el reloj local avanza en la componente del emisor
		long[] merged = new long[clock.size()];
		VectorClock c = clock;
		for (int k = 0; k < merged.length; k++) {
			merged[k] = Math.max(c.get(k), m.clock().get(k));
		}
		clock = VectorClock.of(merged);
		delivered.add(m);
	}

	public List<String> conversation() {
		return delivered.stream().map(m -> m.sender() + ": " + m.text()).toList();
	}

	public int pending() {
		return buffer.size();
	}

	public String name() {
		return name;
	}

	public int id() {
		return id;
	}
}
