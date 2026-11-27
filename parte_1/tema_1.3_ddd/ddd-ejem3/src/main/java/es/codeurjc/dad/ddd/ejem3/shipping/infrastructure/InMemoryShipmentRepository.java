package es.codeurjc.dad.ddd.ejem3.shipping.infrastructure;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Repository;

import es.codeurjc.dad.ddd.ejem3.shipping.domain.Shipment;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.ShipmentId;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.ShipmentRepository;

@Repository
public class InMemoryShipmentRepository implements ShipmentRepository {

	private final Map<ShipmentId, Shipment> shipments = new ConcurrentHashMap<>();

	@Override
	public ShipmentId nextId() {
		return new ShipmentId("SH-" + UUID.randomUUID().toString().substring(0, 8));
	}

	@Override
	public void save(Shipment shipment) {
		shipments.put(shipment.id(), shipment);
	}

	@Override
	public Optional<Shipment> findByOrderReference(String orderReference) {
		return shipments.values().stream().filter(s -> s.orderReference().equals(orderReference)).findFirst();
	}

	@Override
	public List<Shipment> findAll() {
		return List.copyOf(shipments.values());
	}
}
