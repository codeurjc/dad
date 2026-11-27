package es.codeurjc.dad.ddd.ejem2.infrastructure.events;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import es.codeurjc.dad.ddd.ejem2.domain.OrderCancelled;
import es.codeurjc.dad.ddd.ejem2.domain.OrderPlaced;

/**
 * Reacciona a los eventos de dominio. El agregado Order no sabe que existe:
 * podríamos añadir más reacciones sin tocar el dominio.
 */
@Component
public class OrderEventsListener {

	private static final Logger log = LoggerFactory.getLogger(OrderEventsListener.class);

	@EventListener
	public void on(OrderPlaced event) {
		log.info("Pedido {} confirmado por {} ({} unidades, {}). Enviando email de confirmación...",
				event.orderId(), event.customerId(), event.units(), event.total());
	}

	@EventListener
	public void on(OrderCancelled event) {
		log.info("Pedido {} cancelado. Avisando al cliente {}...", event.orderId(), event.customerId());
	}
}
