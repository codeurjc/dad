package es.codeurjc.dad.k8s.ejem3;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CalculoController {

	private final String version;
	private final String pod;

	public CalculoController(@Value("${app.version:dev}") String version) {
		this.version = version;
		this.pod = hostname();
	}

	@GetMapping("/primos")
	public Map<String, Object> primos(@RequestParam(defaultValue = "200000") int hasta) {
		return Map.of("hasta", hasta, "primos", Primos.contarHasta(Math.min(hasta, 5_000_000)),
				"version", version, "pod", pod);
	}

	@GetMapping("/version")
	public Map<String, String> version() {
		return Map.of("version", version, "pod", pod);
	}

	private static String hostname() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			return "desconocido";
		}
	}
}
