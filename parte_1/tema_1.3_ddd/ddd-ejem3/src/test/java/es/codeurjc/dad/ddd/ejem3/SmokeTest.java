package es.codeurjc.dad.ddd.ejem3;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import es.codeurjc.dad.ddd.ejem3.sales.api.OrderPlacedEvent.Item;
import es.codeurjc.dad.ddd.ejem3.sales.application.SalesService;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.Shipment;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.ShipmentRepository;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.ShipmentStatus;

/**
 * Comprobacion minima: un pedido confirmado en Ventas acaba como un envio
 * reservado en Logistica.
 */
@SpringBootTest
class SmokeTest {

	@Autowired
	private SalesService sales;

	@Autowired
	private ShipmentRepository shipments;

	@Test
	void unPedidoDeVentasGeneraUnEnvioEnLogistica() {
		String orderId = sales.placeOrder("Luis", "C/ Mayor 1", "Madrid", "28013", List.of(new Item("LAPTOP", 1)));

		Shipment shipment = shipments.findByOrderReference(orderId).orElseThrow();
		assertEquals(ShipmentStatus.BOOKED, shipment.status());
		assertEquals(2_100, shipment.weightGrams());
	}
}
