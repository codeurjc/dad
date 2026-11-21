package es.codeurjc.dad.ddd.ejem3.shipping.domain;

import java.util.List;
import java.util.Optional;

public interface ShipmentRepository {

	ShipmentId nextId();

	void save(Shipment shipment);

	Optional<Shipment> findByOrderReference(String orderReference);

	List<Shipment> findAll();
}
