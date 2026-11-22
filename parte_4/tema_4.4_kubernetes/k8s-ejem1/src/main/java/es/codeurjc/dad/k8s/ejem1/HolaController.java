package es.codeurjc.dad.k8s.ejem1;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HolaController {

	private final String mensaje;
	private final String version;
	private final boolean apiKeyConfigurada;
	private final String pod;

	public HolaController(
			// Vienen de variables de entorno: el ConfigMap (APP_MENSAJE) y el Secret (APP_API_KEY)
			@Value("${app.mensaje:Hola desde un contenedor}") String mensaje,
			@Value("${app.version:v1}") String version,
			@Value("${app.api-key:}") String apiKey) {
		this.mensaje = mensaje;
		this.version = version;
		this.apiKeyConfigurada = !apiKey.isBlank();
		this.pod = hostname();
	}

	@GetMapping("/")
	public Map<String, Object> hola() {
		Map<String, Object> respuesta = new LinkedHashMap<>();
		respuesta.put("mensaje", mensaje);
		respuesta.put("version", version);
		// En Kubernetes el hostname es el nombre del pod: así se ve qué réplica responde
		respuesta.put("pod", pod);
		// Nunca devolver un secreto: solo si está configurado
		respuesta.put("apiKeyConfigurada", apiKeyConfigurada);
		return respuesta;
	}

	static String hostname() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			return "desconocido";
		}
	}
}
