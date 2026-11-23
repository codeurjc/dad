package es.codeurjc.dad.balanceo.ejer1.proxy;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import es.codeurjc.dad.balanceo.ejer1.lb.Backend;
import es.codeurjc.dad.balanceo.ejer1.lb.LoadBalancer;

/**
 * Comprobación de salud ACTIVA: cada pocos segundos pregunta a cada servidor.
 * Un servidor que no responde 2xx deja de recibir peticiones; cuando vuelve a
 * responder, se reincorpora.
 */
@Component
public class HealthChecker {

	private static final Logger log = LoggerFactory.getLogger(HealthChecker.class);

	private final LoadBalancer lb;
	private final String path;
	private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();

	public HealthChecker(LoadBalancer lb, @Value("${lb.health.path}") String path) {
		this.lb = lb;
		this.path = path;
	}

	@Scheduled(fixedDelayString = "${lb.health.interval-ms}")
	public void check() {
		for (Backend b : lb.backends()) {
			boolean ok = ping(b);
			if (ok != b.isHealthy()) {
				log.warn("{} pasa a estar {}", b.id(), ok ? "DISPONIBLE" : "CAÍDO");
			}
			b.markHealthy(ok);
		}
	}

	private boolean ping(Backend b) {
		try {
			HttpRequest request = HttpRequest.newBuilder(b.uri().resolve(path)).timeout(Duration.ofSeconds(1)).GET()
					.build();
			int status = http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
			return status >= 200 && status < 300;
		} catch (Exception e) {
			if (e instanceof InterruptedException) {
				Thread.currentThread().interrupt();
			}
			return false;
		}
	}
}
