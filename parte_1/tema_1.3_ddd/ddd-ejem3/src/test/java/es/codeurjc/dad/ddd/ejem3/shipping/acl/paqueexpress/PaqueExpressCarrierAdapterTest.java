package es.codeurjc.dad.ddd.ejem3.shipping.acl.paqueexpress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import es.codeurjc.dad.ddd.ejem3.shipping.domain.CarrierException;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.Recipient;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.Shipment;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.ShipmentId;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.TrackingNumber;

class PaqueExpressCarrierAdapterTest {

	private final PaqueExpressCarrierAdapter acl = new PaqueExpressCarrierAdapter(new PaqueExpressLegacyClient());

	private Shipment shipment(String postalCode, int grams) {
		return new Shipment(new ShipmentId("SH-1"), "SO-1",
				new Recipient("Ana García", "C/ Tulipán", "Móstoles", postalCode), grams);
	}

	@Test
	void traduceNuestroModeloAlDelTransportista() {
		Map<String, String> datos = PaqueExpressCarrierAdapter.toPaqueExpress(shipment("28933", 2750));

		assertEquals("ANA GARCÍA", datos.get("DEST_NOM"));
		assertEquals("2,75", datos.get("PESO_KG"));
		assertEquals("N", datos.get("TIPO_SRV"));
	}

	@Test
	void losEnviosPesadosUsanElServicioDeCarga() {
		Map<String, String> datos = PaqueExpressCarrierAdapter.toPaqueExpress(shipment("28933", 65_000));
		assertEquals("C", datos.get("TIPO_SRV"));
	}

	@Test
	void traduceLaRespuestaANuestroModelo() {
		TrackingNumber tracking = acl.book(shipment("28933", 1000));
		assertTrue(tracking.value().startsWith("PX"));
	}

	@Test
	void losCodigosDeErrorSeTraducenAExcepcionesDelDominio() {
		CarrierException e = assertThrows(CarrierException.class, () -> acl.book(shipment("07001", 1000)));
		assertTrue(e.getMessage().contains("07001"));
	}
}
