package es.codeurjc.dad.balanceo.ejem4;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint que consume CPU durante el tiempo indicado. Sirve para generar
 * carga y ver cómo el HorizontalPodAutoscaler añade réplicas.
 *
 * La aplicación es STATELESS: no guarda nada entre peticiones, así que
 * cualquier réplica puede atender cualquier petición y se pueden crear y
 * destruir réplicas en cualquier momento.
 */
@RestController
public class WorkController {

	public record WorkResult(String instance, long millis, long iterations) {
	}

	private final String instance = hostname();

	@GetMapping("/work")
	public WorkResult work(@RequestParam(defaultValue = "100") long ms) {
		long end = System.nanoTime() + Math.min(ms, 5_000) * 1_000_000;
		long iterations = 0;
		double x = 0;
		while (System.nanoTime() < end) {
			x += Math.sqrt(iterations++);
		}
		return new WorkResult(instance, ms, iterations + (x < 0 ? 1 : 0));
	}

	private static String hostname() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			return "desconocido";
		}
	}
}
