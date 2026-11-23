package es.codeurjc.dad.obs.ejem3.inventario;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

/**
 * Inventario busca el producto en varios almacenes, uno detrás de otro. Para
 * los productos voluminosos tiene que consultar además el almacén externo, que
 * es lento: en la traza se ve claramente qué span se come el tiempo.
 */
@RestController
public class StockController {

	public record Availability(String product, int units, String warehouse) {
	}

	private static final Logger log = LoggerFactory.getLogger(StockController.class);
	private static final List<String> WAREHOUSES = List.of("madrid", "barcelona", "externo");

	private final ObservationRegistry observations;

	public StockController(ObservationRegistry observations) {
		this.observations = observations;
	}

	@GetMapping("/stock/{product}")
	public Availability stock(@PathVariable String product) {
		boolean bulky = product.startsWith("portatil") || product.startsWith("tele");
		for (String warehouse : WAREHOUSES) {
			if (warehouse.equals("externo") && !bulky) {
				break;
			}
			int units = Observation.createNotStarted("inventario.warehouse.query", observations)
					.lowCardinalityKeyValue("warehouse", warehouse)
					.highCardinalityKeyValue("product", product) // solo en la traza, no en métricas
					.observe(() -> query(warehouse, product));
			if (units > 0) {
				log.info("{} disponible en {}", product, warehouse);
				return new Availability(product, units, warehouse);
			}
		}
		log.warn("{} agotado", product);
		return new Availability(product, 0, "ninguno");
	}

	private int query(String warehouse, String product) {
		long ms = switch (warehouse) {
			case "madrid" -> 20;
			case "barcelona" -> 35;
			default -> 800; // el almacén externo es LENTO
		};
		try {
			Thread.sleep(ms);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		boolean inStock = switch (warehouse) {
			case "madrid" -> product.hashCode() % 2 == 0;
			case "barcelona" -> !product.startsWith("portatil");
			default -> true;
		};
		return inStock ? 3 : 0;
	}
}
