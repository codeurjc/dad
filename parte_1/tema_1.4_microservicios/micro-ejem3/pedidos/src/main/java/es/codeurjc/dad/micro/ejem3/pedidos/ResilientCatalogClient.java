package es.codeurjc.dad.micro.ejem3.pedidos;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import es.codeurjc.dad.micro.ejem3.pedidos.resilience.Bulkhead;
import es.codeurjc.dad.micro.ejem3.pedidos.resilience.CircuitBreaker;
import es.codeurjc.dad.micro.ejem3.pedidos.resilience.Retry;

/**
 * Cliente del catálogo protegido con varias capas de resiliencia:
 *
 * <pre>
 * fallback( retry( circuitBreaker( bulkhead( timeout( llamada HTTP ) ) ) ) )
 * </pre>
 *
 * <ol>
 * <li><b>Timeout</b>: nunca esperar indefinidamente.</li>
 * <li><b>Bulkhead</b>: como mucho N llamadas a la vez al catálogo.</li>
 * <li><b>Circuit breaker</b>: si el catálogo falla mucho, dejar de llamarlo un rato.</li>
 * <li><b>Retry</b>: reintentar los errores transitorios con espera exponencial.</li>
 * <li><b>Fallback</b>: si todo falla, usar el último dato conocido (caché).</li>
 * </ol>
 */
@Component
public class ResilientCatalogClient {

	public record Lookup(ProductInfo product, boolean fromCache) {
	}

	private static final Logger log = LoggerFactory.getLogger(ResilientCatalogClient.class);

	private final RestClient http;
	private final Retry retry;
	private final CircuitBreaker circuitBreaker;
	private final Bulkhead bulkhead;
	private final Map<Long, ProductInfo> lastKnown = new ConcurrentHashMap<>();

	public ResilientCatalogClient(@Value("${catalogo.url}") String url,
			@Value("${catalogo.connect-timeout}") Duration connectTimeout,
			@Value("${catalogo.read-timeout}") Duration readTimeout,
			@Value("${catalogo.retry.max-attempts}") int maxAttempts,
			@Value("${catalogo.retry.initial-backoff}") Duration initialBackoff,
			@Value("${catalogo.circuit-breaker.failure-threshold}") double failureThreshold,
			@Value("${catalogo.circuit-breaker.window-size}") int windowSize,
			@Value("${catalogo.circuit-breaker.open-duration}") Duration openDuration,
			@Value("${catalogo.bulkhead.max-concurrent-calls}") int maxConcurrentCalls) {

		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(connectTimeout);
		requestFactory.setReadTimeout(readTimeout);
		this.http = RestClient.builder().baseUrl(url).requestFactory(requestFactory).build();

		this.retry = new Retry(maxAttempts, initialBackoff, ResilientCatalogClient::isTransient);
		this.circuitBreaker = new CircuitBreaker(failureThreshold, windowSize, openDuration, Clock.systemUTC());
		this.bulkhead = new Bulkhead(maxConcurrentCalls);
	}

	/** Solo merece la pena reintentar fallos de red, timeouts y errores 5xx. */
	static boolean isTransient(RuntimeException e) {
		return e instanceof ResourceAccessException || e instanceof HttpServerErrorException;
	}

	public Optional<Lookup> findProduct(Long id) {
		try {
			ProductInfo product = retry.call(() -> circuitBreaker.call(() -> bulkhead.call(() -> fetch(id))));
			if (product == null) {
				return Optional.empty();
			}
			lastKnown.put(id, product);
			return Optional.of(new Lookup(product, false));
		} catch (HttpClientErrorException.NotFound e) {
			return Optional.empty();
		} catch (RuntimeException e) {
			ProductInfo cached = lastKnown.get(id);
			if (cached != null) {
				log.warn("Catálogo no disponible ({}): se usa el último precio conocido de {}", e.getMessage(), id);
				return Optional.of(new Lookup(cached, true));
			}
			throw new CatalogUnavailableException("El catálogo no está disponible", e);
		}
	}

	private ProductInfo fetch(Long id) {
		return http.get().uri("/products/{id}", id).retrieve().body(ProductInfo.class);
	}

	public CircuitBreaker.State circuitState() {
		return circuitBreaker.state();
	}

	public int availableBulkheadPermits() {
		return bulkhead.availablePermits();
	}
}
