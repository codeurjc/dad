package es.codeurjc.dad.micro.ejem3.pedidos;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * <pre>
 * curl -X POST localhost:8082/orders -H 'Content-Type: application/json' -d '{"productId":1,"quantity":2}'
 * curl localhost:8082/resilience
 * </pre>
 */
@RestController
public class OrderController {

	public record PlaceOrderRequest(Long productId, int quantity) {
	}

	public record Order(long id, Long productId, String productName, BigDecimal total, boolean priceFromCache) {
	}

	private final ResilientCatalogClient catalog;
	private final List<Order> orders = new CopyOnWriteArrayList<>();
	private final AtomicLong ids = new AtomicLong();

	public OrderController(ResilientCatalogClient catalog) {
		this.catalog = catalog;
	}

	@PostMapping("/orders")
	@ResponseStatus(HttpStatus.CREATED)
	public Order place(@RequestBody PlaceOrderRequest request) {
		ResilientCatalogClient.Lookup lookup = catalog.findProduct(request.productId())
				.orElseThrow(() -> new IllegalArgumentException("No existe el producto " + request.productId()));
		ProductInfo p = lookup.product();
		Order order = new Order(ids.incrementAndGet(), p.id(), p.name(),
				p.price().multiply(BigDecimal.valueOf(request.quantity())), lookup.fromCache());
		orders.add(order);
		return order;
	}

	@GetMapping("/orders")
	public List<Order> orders() {
		return orders;
	}

	@GetMapping("/resilience")
	public Map<String, Object> resilience() {
		return Map.of("circuitBreaker", catalog.circuitState(), "bulkheadFreePermits",
				catalog.availableBulkheadPermits());
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public String notFound(IllegalArgumentException e) {
		return e.getMessage();
	}

	/** Degradación controlada: un 503 rápido y claro en lugar de un timeout. */
	@ExceptionHandler(CatalogUnavailableException.class)
	@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
	public String unavailable(CatalogUnavailableException e) {
		return e.getMessage() + ": inténtalo de nuevo en unos segundos";
	}
}
