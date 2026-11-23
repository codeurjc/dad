package es.codeurjc.dad.k8s.ejem2;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NotaController {

	private final NotaRepository notas;
	private final String pod;

	public NotaController(NotaRepository notas) {
		this.notas = notas;
		this.pod = hostname();
	}

	@GetMapping("/api/notas")
	public List<Nota> listar() {
		return notas.findAll();
	}

	@PostMapping("/api/notas")
	public Nota crear(@RequestBody Map<String, String> cuerpo) {
		return notas.save(new Nota(cuerpo.get("texto"), pod));
	}

	@GetMapping("/")
	public Map<String, Object> info() {
		return Map.of("pod", pod, "notas", notas.count());
	}

	private static String hostname() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			return "desconocido";
		}
	}
}
