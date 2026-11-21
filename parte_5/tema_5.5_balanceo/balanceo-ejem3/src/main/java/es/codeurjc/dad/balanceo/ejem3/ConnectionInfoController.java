package es.codeurjc.dad.balanceo.ejem3;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Muestra cómo ve la conexión la instancia que atiende la petición.
 * Compara la respuesta en cada modo:
 *
 * <pre>
 *              | scheme del servidor | TLS en la instancia | IP cliente visible
 * passthrough  | https               | sí (cifra la app)   | no: ve la IP del balanceador
 * terminación  | http (+X-Fwd-Proto) | no                  | sí: X-Forwarded-For
 * re-cifrado   | https               | sí (2 conexiones)   | sí: X-Forwarded-For
 * </pre>
 */
@RestController
public class ConnectionInfoController {

	public record ConnectionInfo(String instance, String scheme, boolean secure, String tlsCipher,
			String remoteAddr, String xForwardedFor, String xForwardedProto, String host) {
	}

	private final String instance = hostname();

	@GetMapping("/")
	public ConnectionInfo info(HttpServletRequest request) {
		return new ConnectionInfo(instance, request.getScheme(), request.isSecure(),
				(String) request.getAttribute("jakarta.servlet.request.cipher_suite"),
				request.getRemoteAddr(), request.getHeader("X-Forwarded-For"),
				request.getHeader("X-Forwarded-Proto"), request.getHeader("Host"));
	}

	private static String hostname() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			return "desconocido";
		}
	}
}
