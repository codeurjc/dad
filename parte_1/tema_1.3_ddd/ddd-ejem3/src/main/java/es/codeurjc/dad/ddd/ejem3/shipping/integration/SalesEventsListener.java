package es.codeurjc.dad.ddd.ejem3.shipping.integration;

import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import es.codeurjc.dad.ddd.ejem3.shipping.application.ShippingService;
import es.codeurjc.dad.ddd.ejem3.sales.api.OrderPlacedEvent;

/**
 * Punto de entrada de Logística para los eventos de Ventas.
 */
@Component
public class SalesEventsListener {

	private final ShippingService shipping;

	public SalesEventsListener(ShippingService shipping) {
		this.shipping = shipping;
	}

	@EventListener
	public void on(OrderPlacedEvent event) {
		shipping.scheduleShipment(event.orderId(),
				SalesEventsTranslator.recipientOf(event),
				SalesEventsTranslator.unitsByProduct(event));
	}
}
