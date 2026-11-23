package es.codeurjc.dad.balanceo.ejem1;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

/**
 * Devuelve qué instancia ha atendido la petición y cuántas veces ha visitado
 * el usuario la página EN ESTA SESIÓN.
 *
 * La sesión vive en la memoria de la instancia. Si el balanceador manda cada
 * petición a una instancia distinta (round robin), el contador "se reinicia":
 * cada instancia tiene su propia sesión. Con sticky sessions, todas las
 * peticiones del usuario van a la misma instancia y el contador crece.
 */
@RestController
public class InstanceController {

	public record Visit(String instance, String sessionId, int visits) {
	}

	private final String instance;

	public InstanceController() {
		this(hostname());
	}

	InstanceController(String instance) {
		this.instance = instance;
	}

	@GetMapping("/")
	public Visit visit(HttpSession session) {
		Integer visits = (Integer) session.getAttribute("visits");
		visits = visits == null ? 1 : visits + 1;
		session.setAttribute("visits", visits);
		return new Visit(instance, session.getId(), visits);
	}

	@GetMapping("/instance")
	public String instance() {
		return instance;
	}

	private static String hostname() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			return "desconocido";
		}
	}
}
