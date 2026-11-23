package es.codeurjc.dad.micro.ejem3.catalogo;

import java.math.BigDecimal;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * <pre>
 * curl localhost:8081/products/1
 * curl -X PUT localhost:8081/chaos -H 'Content-Type: application/json' -d '{"latencyMs":3000,"failureRate":0}'
 * curl -X PUT localhost:8081/chaos -H 'Content-Type: application/json' -d '{"latencyMs":0,"failureRate":0.8}'
 * curl -X PUT localhost:8081/chaos -H 'Content-Type: application/json' -d '{"latencyMs":0,"failureRate":0}'
 * </pre>
 */
@RestController
public class ProductController {

	public record Product(Long id, String name, BigDecimal price) {
	}

	private static final Map<Long, Product> PRODUCTS = Map.of(
			1L, new Product(1L, "Domain-Driven Design", new BigDecimal("54.90")),
			2L, new Product(2L, "Microservices Patterns", new BigDecimal("49.50")),
			3L, new Product(3L, "Release It!", new BigDecimal("39.90")));

	private final Chaos chaos;

	public ProductController(Chaos chaos) {
		this.chaos = chaos;
	}

	@GetMapping("/products/{id}")
	public ResponseEntity<Product> product(@PathVariable Long id) throws InterruptedException {
		chaos.apply();
		Product p = PRODUCTS.get(id);
		return p == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(p);
	}

	@GetMapping("/chaos")
	public Chaos.Settings chaos() {
		return chaos.settings();
	}

	@PutMapping("/chaos")
	public Chaos.Settings chaos(@RequestBody Chaos.Settings settings) {
		chaos.update(settings);
		return settings;
	}

	@ExceptionHandler(Chaos.ChaosException.class)
	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	public String failed(Chaos.ChaosException e) {
		return e.getMessage();
	}
}
