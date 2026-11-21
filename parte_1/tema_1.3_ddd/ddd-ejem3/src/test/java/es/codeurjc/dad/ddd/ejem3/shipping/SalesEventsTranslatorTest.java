package es.codeurjc.dad.ddd.ejem3.shipping;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import es.codeurjc.dad.ddd.ejem3.sales.api.OrderPlacedEvent;
import es.codeurjc.dad.ddd.ejem3.sales.api.OrderPlacedEvent.Item;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.Recipient;
import es.codeurjc.dad.ddd.ejem3.shipping.integration.SalesEventsTranslator;

class SalesEventsTranslatorTest {

	private final OrderPlacedEvent event = new OrderPlacedEvent("SO-1", "Ana", "C/ Tulipán", "Móstoles", "28933",
			List.of(new Item("BOOK-DDD", 1), new Item("MUG-URJC", 2), new Item("BOOK-DDD", 3)));

	@Test
	void elClienteDeVentasEsUnDestinatarioEnLogistica() {
		assertEquals(new Recipient("Ana", "C/ Tulipán", "Móstoles", "28933"),
				SalesEventsTranslator.recipientOf(event));
	}

	@Test
	void agrupaLasUnidadesPorProducto() {
		assertEquals(Map.of("BOOK-DDD", 4, "MUG-URJC", 2), SalesEventsTranslator.unitsByProduct(event));
	}
}
