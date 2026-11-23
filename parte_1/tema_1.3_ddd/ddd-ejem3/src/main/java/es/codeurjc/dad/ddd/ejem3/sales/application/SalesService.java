package es.codeurjc.dad.ddd.ejem3.sales.application;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import es.codeurjc.dad.ddd.ejem3.sales.api.OrderPlacedEvent;
import es.codeurjc.dad.ddd.ejem3.sales.api.OrderPlacedEvent.Item;

/**
 * Contexto de Ventas. Para Ventas un pedido es un cliente, unos productos y
 * unos precios. No sabe nada de pesos, bultos ni transportistas.
 *
 * (El modelo interno de Ventas se ha simplificado al máximo: lo interesante
 * de este ejemplo son las fronteras entre contextos.)
 */
@Service
public class SalesService {

	private static final Logger log = LoggerFactory.getLogger(SalesService.class);

	private final ApplicationEventPublisher events;

	public SalesService(ApplicationEventPublisher events) {
		this.events = events;
	}

	public String placeOrder(String customerName, String street, String city, String postalCode, List<Item> items) {
		String orderId = "SO-" + UUID.randomUUID().toString().substring(0, 8);
		log.info("[Ventas] Pedido {} confirmado para {}", orderId, customerName);
		events.publishEvent(new OrderPlacedEvent(orderId, customerName, street, city, postalCode, items));
		return orderId;
	}
}
