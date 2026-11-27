package es.codeurjc.dad.fund.ejem2;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Una réplica del almacén clave-valor. Puede estar caída. */
public class Replica {

	private final String name;
	private final Map<String, Versioned> data = new HashMap<>();
	private boolean up = true;

	public Replica(String name) {
		this.name = name;
	}

	/** Solo aplica la escritura si es más nueva que lo que ya tiene. */
	public void write(String key, Versioned v) {
		requireUp();
		data.merge(key, v, (old, nu) -> nu.version() > old.version() ? nu : old);
	}

	public Optional<Versioned> read(String key) {
		requireUp();
		return Optional.ofNullable(data.get(key));
	}

	private void requireUp() {
		if (!up) {
			throw new IllegalStateException(name + " está caída");
		}
	}

	public void crash() {
		up = false;
	}

	public void recover() {
		up = true;
	}

	public boolean isUp() {
		return up;
	}

	public String name() {
		return name;
	}

	/** Para los tests y la demo: lo que hay guardado, aunque esté caída. */
	public Optional<Versioned> peek(String key) {
		return Optional.ofNullable(data.get(key));
	}
}
