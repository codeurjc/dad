package es.codeurjc.dad.fund.ejem3;

import java.util.List;

/** Mensajes del protocolo Raft (solo los dos RPC básicos y sus respuestas). */
public final class Messages {

	private Messages() {
	}

	public sealed interface Message {

		long term();
	}

	/** Un candidato pide el voto. Incluye cómo de actualizado está su log. */
	public record RequestVote(long term, int candidate, int lastLogIndex, long lastLogTerm) implements Message {
	}

	public record Vote(long term, boolean granted) implements Message {
	}

	/** El líder replica entradas (o, sin entradas, es un latido). */
	public record AppendEntries(long term, int leader, int prevLogIndex, long prevLogTerm, List<Entry> entries,
			int leaderCommit) implements Message {
	}

	public record AppendResult(long term, boolean success, int matchIndex) implements Message {
	}

	/** Una entrada del log: la orden y el mandato (term) en que la creó el líder. */
	public record Entry(long term, String command) {
	}
}
