package es.codeurjc.dad.eventos.ejem1;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.stereotype.Component;

/**
 * Registro de lo que han hecho los listeners (para verlo en los tests y en GET /log).
 */
@Component
public class EventLog {

	private final List<String> entries = new CopyOnWriteArrayList<>();

	public void add(String entry) {
		entries.add(entry);
	}

	public List<String> entries() {
		return List.copyOf(entries);
	}

	public boolean contains(String entry) {
		return entries.contains(entry);
	}
}
