package es.codeurjc.dad.ddd.ejem3.shipping.integration;

import java.util.Map;
import java.util.stream.Collectors;

import es.codeurjc.dad.ddd.ejem3.shipping.domain.Recipient;
import es.codeurjc.dad.ddd.ejem3.sales.api.OrderPlacedEvent;

/**
 * Traduce el lenguaje publicado de Ventas al lenguaje de Logística.
 *
 * Es la ÚNICA clase de Logística que conoce OrderPlacedEvent. Si Ventas
 * cambiase su contrato, solo habría que tocar aquí.
 */
public final class SalesEventsTranslator {

	private SalesEventsTranslator() {
	}

	public static Recipient recipientOf(OrderPlacedEvent event) {
		return new Recipient(event.customerName(), event.street(), event.city(), event.postalCode());
	}

	public static Map<String, Integer> unitsByProduct(OrderPlacedEvent event) {
		return event.items().stream()
				.collect(Collectors.toMap(OrderPlacedEvent.Item::productCode, OrderPlacedEvent.Item::quantity,
						Integer::sum));
	}
}
