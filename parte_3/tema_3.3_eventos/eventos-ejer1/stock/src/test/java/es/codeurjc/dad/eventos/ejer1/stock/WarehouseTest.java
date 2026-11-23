package es.codeurjc.dad.eventos.ejer1.stock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

class WarehouseTest {

	private final Warehouse warehouse = new Warehouse(Map.of("taza", 3));

	@Test
	void reservarDescuentaUnidades() {
		assertTrue(warehouse.reserve("P-1", "taza", 2));
		assertEquals(1, warehouse.available("taza"));
	}

	@Test
	void sinUnidadesSuficientesSeRechaza() {
		assertFalse(warehouse.reserve("P-1", "taza", 4));
		assertEquals(3, warehouse.available("taza"));
	}

	@Test
	void reservarDosVecesElMismoPedidoEsIdempotente() {
		warehouse.reserve("P-1", "taza", 2);
		assertTrue(warehouse.reserve("P-1", "taza", 2));
		assertEquals(1, warehouse.available("taza"));
	}

	@Test
	void laCompensacionDevuelveLasUnidadesUnaSolaVez() {
		warehouse.reserve("P-1", "taza", 2);

		assertTrue(warehouse.release("P-1"));
		assertFalse(warehouse.release("P-1"));
		assertEquals(3, warehouse.available("taza"));
	}
}
