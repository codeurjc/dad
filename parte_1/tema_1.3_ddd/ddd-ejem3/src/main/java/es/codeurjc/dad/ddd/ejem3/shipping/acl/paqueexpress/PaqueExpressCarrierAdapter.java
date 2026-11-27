package es.codeurjc.dad.ddd.ejem3.shipping.acl.paqueexpress;

import java.util.Locale;
import java.util.Map;

import es.codeurjc.dad.ddd.ejem3.shipping.domain.CarrierException;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.CarrierGateway;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.Shipment;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.TrackingNumber;

/**
 * Anti-Corruption Layer (ACL) entre Logística y PaqueExpress.
 *
 * Implementa el puerto CarrierGateway (lenguaje de Logística) traduciendo en
 * ambos sentidos:
 * <ul>
 * <li>Shipment → mapa de datos de PaqueExpress (kilos, códigos de servicio...)</li>
 * <li>códigos de respuesta de PaqueExpress → TrackingNumber o CarrierException</li>
 * </ul>
 * Ninguna clase fuera de este paquete conoce PaqueExpress. Cambiar de
 * transportista supone escribir otro adaptador, sin tocar el dominio.
 */
public class PaqueExpressCarrierAdapter implements CarrierGateway {

	private final PaqueExpressLegacyClient client;

	public PaqueExpressCarrierAdapter(PaqueExpressLegacyClient client) {
		this.client = client;
	}

	@Override
	public TrackingNumber book(Shipment shipment) {
		Map<String, String> respuesta = client.altaExpedicion(toPaqueExpress(shipment));
		return switch (respuesta.get("COD_RES")) {
			case "00" -> new TrackingNumber(respuesta.get("NUM_EXP"));
			case "17" -> throw new CarrierException(
					"El transportista no da servicio en el código postal " + shipment.recipient().postalCode());
			case "23" -> throw new CarrierException("Peso excesivo para el servicio contratado");
			default -> throw new CarrierException("Error desconocido del transportista: " + respuesta.get("COD_RES"));
		};
	}

	static Map<String, String> toPaqueExpress(Shipment shipment) {
		String kilos = String.format(Locale.of("es", "ES"), "%.2f", shipment.weightGrams() / 1000.0);
		return Map.of(
				"DEST_NOM", shipment.recipient().name().toUpperCase(Locale.ROOT),
				"DEST_DIR", shipment.recipient().street(),
				"DEST_POB", shipment.recipient().city(),
				"DEST_CP", shipment.recipient().postalCode(),
				"PESO_KG", kilos,
				"TIPO_SRV", shipment.requiresFreightService() ? "C" : "N",
				"REF_CLI", shipment.orderReference());
	}
}
