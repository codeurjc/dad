package es.codeurjc.dad.micro.ejer1.prestamos;

import java.time.Clock;
import java.time.Duration;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import es.codeurjc.dad.micro.ejer1.prestamos.resilience.CircuitBreaker;

/**
 * Cliente HTTP del servicio de libros con timeouts y circuit breaker.
 *
 * NO reintentamos: checkout y return NO son idempotentes (reintentar un
 * checkout cuya respuesta se perdió reservaría dos ejemplares). Para poder
 * reintentar habría que hacerlos idempotentes (p. ej. con un identificador
 * de préstamo que libros recuerde).
 */
@Component
public class RestLibrosClient implements LibrosClient {

	private final RestClient http;
	private final CircuitBreaker circuitBreaker = new CircuitBreaker(0.5, 6, Duration.ofSeconds(15),
			Clock.systemUTC());

	public RestLibrosClient(@Value("${libros.url}") String url,
			@Value("${libros.connect-timeout}") Duration connectTimeout,
			@Value("${libros.read-timeout}") Duration readTimeout) {
		SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
		factory.setConnectTimeout(connectTimeout);
		factory.setReadTimeout(readTimeout);
		this.http = RestClient.builder().baseUrl(url).requestFactory(factory).build();
	}

	@Override
	public BookInfo checkout(String isbn) {
		return protect(() -> http.post().uri("/books/{isbn}/checkout", isbn).retrieve().body(BookInfo.class), isbn);
	}

	@Override
	public void giveBack(String isbn) {
		protect(() -> http.post().uri("/books/{isbn}/return", isbn).retrieve().toBodilessEntity(), isbn);
	}

	@SuppressWarnings("unchecked")
	private <T> T protect(Supplier<T> call, String isbn) {
		Object result;
		try {
			result = circuitBreaker.call(() -> {
				try {
					return call.get();
				} catch (HttpClientErrorException e) {
					// Un 4xx es una respuesta correcta del servicio (el libro no existe,
					// no quedan ejemplares): NO cuenta como fallo para el circuit breaker
					return e;
				}
			});
		} catch (RuntimeException e) {
			// Timeouts, conexión rechazada, 5xx o circuito abierto
			throw new LibrosUnavailableException(e);
		}
		if (result instanceof HttpClientErrorException e) {
			return translate(e, isbn);
		}
		return (T) result;
	}

	private static <T> T translate(HttpClientErrorException e, String isbn) {
		if (e.getStatusCode().value() == HttpStatus.NOT_FOUND.value()) {
			throw new BookNotFoundException(isbn);
		}
		if (e.getStatusCode().value() == HttpStatus.CONFLICT.value()) {
			throw new NoCopiesAvailableException(e.getResponseBodyAsString());
		}
		throw e;
	}

	public CircuitBreaker.State circuitState() {
		return circuitBreaker.state();
	}
}
