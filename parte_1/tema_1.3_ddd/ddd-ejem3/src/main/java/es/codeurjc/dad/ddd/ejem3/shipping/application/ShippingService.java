package es.codeurjc.dad.ddd.ejem3.shipping.application;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import es.codeurjc.dad.ddd.ejem3.shipping.domain.CarrierGateway;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.ProductWeights;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.Recipient;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.Shipment;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.ShipmentRepository;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.TrackingNumber;

/**
 * Servicio de aplicación de Logística. Recibe peticiones ya expresadas en el
 * lenguaje de Logística (Recipient, códigos de producto y unidades).
 */
@Service
public class ShippingService {

	private static final Logger log = LoggerFactory.getLogger(ShippingService.class);

	private final ShipmentRepository shipments;
	private final ProductWeights weights;
	private final CarrierGateway carrier;

	public ShippingService(ShipmentRepository shipments, ProductWeights weights, CarrierGateway carrier) {
		this.shipments = shipments;
		this.weights = weights;
		this.carrier = carrier;
	}

	public Shipment scheduleShipment(String orderReference, Recipient recipient, Map<String, Integer> unitsByProduct) {
		int weight = unitsByProduct.entrySet().stream()
				.mapToInt(e -> weights.gramsOf(e.getKey()) * e.getValue())
				.sum();

		Shipment shipment = new Shipment(shipments.nextId(), orderReference, recipient, weight);
		TrackingNumber tracking = carrier.book(shipment);
		shipment.booked(tracking);
		shipments.save(shipment);

		log.info("[Logística] Envío {} del pedido {} ({} g) reservado con seguimiento {}",
				shipment.id().value(), orderReference, weight, tracking.value());
		return shipment;
	}
}
