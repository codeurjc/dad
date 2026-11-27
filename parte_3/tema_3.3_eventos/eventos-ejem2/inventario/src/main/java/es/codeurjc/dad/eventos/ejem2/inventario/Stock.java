package es.codeurjc.dad.eventos.ejem2.inventario;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stock de productos del almacén (en memoria). Java puro, sin Spring.
 */
public class Stock {

	private final Map<String, Integer> units = new ConcurrentHashMap<>();

	public Stock(Map<String, Integer> initial) {
		units.putAll(initial);
	}

	public void remove(String product, int quantity) {
		units.merge(product, -quantity, Integer::sum);
	}

	public void add(String product, int quantity) {
		units.merge(product, quantity, Integer::sum);
	}

	public int unitsOf(String product) {
		return units.getOrDefault(product, 0);
	}

	public boolean needsRestock(String product) {
		return unitsOf(product) < 5;
	}
}
