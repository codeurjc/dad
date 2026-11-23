package es.codeurjc.dad.obs.ejem3.tienda;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

/**
 * <pre>
 * curl -X POST localhost:8080/purchase -H 'Content-Type: application/json' -d '["libro-ddd","taza"]'
 * curl -X POST localhost:8080/purchase -H 'Content-Type: application/json' -d '["libro-ddd","portatil","taza"]'
 * </pre>
 * Después, en Grafana (http://localhost:3000) -> Explore -> Tempo, busca las
 * trazas del servicio "tienda" y compara las dos.
 */
@RestController
public class PurchaseController {

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record Availability(String product, int units, String warehouse) {
	}

	public record Purchase(List<Availability> items, double shippingCost) {
	}

	private static final Logger log = LoggerFactory.getLogger(PurchaseController.class);

	private final RestClient inventario;
	private final ObservationRegistry observations;

	public PurchaseController(RestClient inventarioClient, ObservationRegistry observations) {
		this.inventario = inventarioClient;
		this.observations = observations;
	}

	@PostMapping("/purchase")
	public Purchase purchase(@RequestBody List<String> products) {
		log.info("Compra de {} productos", products.size());

		// Una llamada HTTP por producto: cada una será un span hijo en la traza
		List<Availability> items = products.stream()
				.map(p -> inventario.get().uri("/stock/{product}", p).retrieve().body(Availability.class))
				.toList();

		// Un span PROPIO para una operación interna que queremos ver en la traza
		double shipping = Observation.createNotStarted("tienda.shipping.calculate", observations)
				.lowCardinalityKeyValue("items", items.size() > 2 ? "many" : "few")
				.observe(() -> calculateShipping(items));

		log.info("Compra lista: gastos de envío {}", shipping);
		return new Purchase(items, shipping);
	}

	private double calculateShipping(List<Availability> items) {
		sleep(15);
		return items.stream().map(Availability::warehouse).distinct().count() * 4.95;
	}

	static void sleep(long ms) {
		try {
			Thread.sleep(ms);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
