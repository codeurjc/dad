package es.codeurjc.dad.eventos.ejem4.eventstore;

import java.util.List;
import java.util.function.Consumer;

import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent;

/**
 * Almacén de eventos: solo permite AÑADIR eventos al final de un stream y
 * leerlos. Nunca se modifican ni se borran (append-only).
 */
public interface EventStore {

	/**
	 * Añade eventos al stream.
	 *
	 * @param expectedVersion número de eventos que el llamante cree que tiene el
	 *                        stream. Si no coincide, otro ha escrito antes:
	 *                        {@link ConcurrencyException} (bloqueo optimista).
	 */
	void append(String streamId, int expectedVersion, List<AccountEvent> events);

	List<AccountEvent> load(String streamId);

	/** Notifica cada evento guardado (lo usan las proyecciones). */
	void subscribe(Consumer<AccountEvent> subscriber);
}
