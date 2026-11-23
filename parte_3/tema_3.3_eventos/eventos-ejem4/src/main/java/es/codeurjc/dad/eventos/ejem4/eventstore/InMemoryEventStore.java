package es.codeurjc.dad.eventos.ejem4.eventstore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent;

/**
 * Event store en memoria. En producción se usaría una base de datos
 * (EventStoreDB, PostgreSQL con una tabla append-only, Kafka...).
 */
public class InMemoryEventStore implements EventStore {

	private final Map<String, List<AccountEvent>> streams = new HashMap<>();
	private final List<Consumer<AccountEvent>> subscribers = new CopyOnWriteArrayList<>();

	@Override
	public void append(String streamId, int expectedVersion, List<AccountEvent> events) {
		synchronized (this) {
			List<AccountEvent> stream = streams.computeIfAbsent(streamId, k -> new ArrayList<>());
			if (stream.size() != expectedVersion) {
				throw new ConcurrencyException(streamId, expectedVersion, stream.size());
			}
			stream.addAll(events);
		}
		events.forEach(e -> subscribers.forEach(s -> s.accept(e)));
	}

	@Override
	public synchronized List<AccountEvent> load(String streamId) {
		return List.copyOf(streams.getOrDefault(streamId, List.of()));
	}

	@Override
	public void subscribe(Consumer<AccountEvent> subscriber) {
		subscribers.add(subscriber);
	}
}
