package es.codeurjc.dad.eventos.ejem2.inventario;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

class StockTest {

	@Test
	void retirarYDevolverUnidades() {
		Stock stock = new Stock(Map.of("taza", 10));
		stock.remove("taza", 7);
		assertEquals(3, stock.unitsOf("taza"));
		assertTrue(stock.needsRestock("taza"));

		stock.add("taza", 7);
		assertEquals(10, stock.unitsOf("taza"));
	}
}
