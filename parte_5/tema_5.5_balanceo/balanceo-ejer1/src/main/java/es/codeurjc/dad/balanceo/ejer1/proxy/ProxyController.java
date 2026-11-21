package es.codeurjc.dad.balanceo.ejer1.proxy;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import es.codeurjc.dad.balanceo.ejer1.lb.Backend;
import es.codeurjc.dad.balanceo.ejer1.lb.LoadBalancer;
import es.codeurjc.dad.balanceo.ejer1.lb.LoadBalancer.Selection;
import es.codeurjc.dad.balanceo.ejer1.lb.NoHealthyBackendException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Proxy inverso de capa 7: recibe la petición del cliente, elige servidor y
 * le reenvía la petición; después devuelve la respuesta al cliente.
 *
 * Además de la comprobación activa, hace una comprobación PASIVA: si un
 * servidor falla al reenviarle una petición, se marca como caído y se
 * reintenta con otro.
 */
@RestController
public class ProxyController {

	public static final String STICKY_COOKIE = "LB_SERVER";

	private static final Logger log = LoggerFactory.getLogger(ProxyController.class);
	private static final Set<String> HOP_BY_HOP = Set.of("connection", "keep-alive", "transfer-encoding",
			"te", "trailer", "upgrade", "host", "content-length");

	private final LoadBalancer lb;
	private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

	public ProxyController(LoadBalancer lb) {
		this.lb = lb;
	}

	@GetMapping("/lb/status")
	public List<String> status() {
		return lb.backends().stream().map(b -> b + " activas=" + b.activeRequests()).toList();
	}

	@RequestMapping("/**")
	public ResponseEntity<byte[]> proxy(HttpServletRequest request) throws IOException, InterruptedException {
		byte[] body = request.getInputStream().readAllBytes();
		String clientIp = request.getRemoteAddr();
		Optional<String> cookie = stickyCookie(request);

		for (int attempt = 0; attempt < 2; attempt++) {
			Selection selection = lb.choose(clientIp, cookie);
			Backend backend = selection.backend();
			backend.requestStarted();
			try {
				HttpResponse<byte[]> response = http.send(forward(request, backend, body, clientIp),
						HttpResponse.BodyHandlers.ofByteArray());
				return toResponse(response, selection);
			} catch (IOException e) {
				log.warn("{} no responde ({}): se marca como caído y se reintenta", backend.id(), e.toString());
				backend.markHealthy(false);
				cookie = Optional.empty();
			} finally {
				backend.requestFinished();
			}
		}
		throw new NoHealthyBackendException();
	}

	private HttpRequest forward(HttpServletRequest request, Backend backend, byte[] body, String clientIp) {
		String pathAndQuery = request.getRequestURI()
				+ (request.getQueryString() != null ? "?" + request.getQueryString() : "");
		HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(backend.uri() + pathAndQuery))
				.timeout(Duration.ofSeconds(30))
				.method(request.getMethod(), HttpRequest.BodyPublishers.ofByteArray(body));
		var names = request.getHeaderNames();
		while (names.hasMoreElements()) {
			String name = names.nextElement();
			if (!HOP_BY_HOP.contains(name.toLowerCase())) {
				var values = request.getHeaders(name);
				while (values.hasMoreElements()) {
					builder.header(name, values.nextElement());
				}
			}
		}
		// El servidor ve la IP del balanceador: le contamos cuál es la del cliente
		builder.header("X-Forwarded-For", clientIp);
		builder.header("X-Forwarded-Host", String.valueOf(request.getHeader("Host")));
		return builder.build();
	}

	private ResponseEntity<byte[]> toResponse(HttpResponse<byte[]> response, Selection selection) {
		HttpHeaders headers = new HttpHeaders();
		response.headers().map().forEach((name, values) -> {
			if (!HOP_BY_HOP.contains(name.toLowerCase()) && !name.startsWith(":")) {
				headers.put(name, values);
			}
		});
		if (selection.setStickyCookie()) {
			headers.add(HttpHeaders.SET_COOKIE, STICKY_COOKIE + "=" + selection.backend().id() + "; Path=/; HttpOnly");
		}
		headers.add("X-Backend", selection.backend().id());
		return ResponseEntity.status(response.statusCode()).headers(headers).body(response.body());
	}

	private static Optional<String> stickyCookie(HttpServletRequest request) {
		if (request.getCookies() == null) {
			return Optional.empty();
		}
		for (Cookie c : request.getCookies()) {
			if (STICKY_COOKIE.equals(c.getName())) {
				return Optional.of(c.getValue());
			}
		}
		return Optional.empty();
	}

	@ExceptionHandler(NoHealthyBackendException.class)
	@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
	public String unavailable(NoHealthyBackendException e) {
		return e.getMessage();
	}
}
