package es.codeurjc.dad.ddd.ejem3.shipping.acl.paqueexpress;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Simula el cliente de la API de un transportista externo, "PaqueExpress".
 *
 * Es un sistema que no controlamos y cuyo modelo es muy distinto al nuestro:
 * claves en mayúsculas con abreviaturas, todo son Strings, el peso va en
 * kilos con coma decimal, el servicio se indica con un código ("N" normal,
 * "C" carga) y los errores se devuelven como códigos numéricos.
 *
 * Si dejásemos que este modelo se filtrase a nuestro dominio, acabaría
 * contaminándolo. Para eso está la Anti-Corruption Layer.
 */
public class PaqueExpressLegacyClient {

	private final AtomicInteger sequence = new AtomicInteger(1000);

	/**
	 * @param datos claves: DEST_NOM, DEST_DIR, DEST_POB, DEST_CP, PESO_KG, TIPO_SRV, REF_CLI
	 * @return claves: COD_RES ("00" = OK, "17" = CP no servido, "23" = peso excesivo), NUM_EXP
	 */
	public Map<String, String> altaExpedicion(Map<String, String> datos) {
		Map<String, String> respuesta = new HashMap<>();
		double pesoKg = Double.parseDouble(datos.get("PESO_KG").replace(',', '.'));
		if (datos.get("DEST_CP").startsWith("07")) {
			respuesta.put("COD_RES", "17");
		} else if ("N".equals(datos.get("TIPO_SRV")) && pesoKg > 30) {
			respuesta.put("COD_RES", "23");
		} else {
			respuesta.put("COD_RES", "00");
			respuesta.put("NUM_EXP", "PX" + sequence.incrementAndGet());
		}
		return respuesta;
	}
}
