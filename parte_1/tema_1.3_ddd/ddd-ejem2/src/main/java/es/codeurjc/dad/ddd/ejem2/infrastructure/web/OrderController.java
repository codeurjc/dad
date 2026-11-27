package es.codeurjc.dad.ddd.ejem2.infrastructure.web;

import java.math.BigDecimal;
import java.net.URI;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import es.codeurjc.dad.ddd.ejem2.application.OrderNotFoundException;
import es.codeurjc.dad.ddd.ejem2.application.OrderService;
import es.codeurjc.dad.ddd.ejem2.domain.CustomerId;
import es.codeurjc.dad.ddd.ejem2.domain.DomainException;
import es.codeurjc.dad.ddd.ejem2.domain.Money;
import es.codeurjc.dad.ddd.ejem2.domain.Order;
import es.codeurjc.dad.ddd.ejem2.domain.OrderId;
import es.codeurjc.dad.ddd.ejem2.domain.ProductId;

/**
 * Adaptador de entrada REST. Traduce HTTP + JSON a llamadas al servicio de
 * aplicación. No contiene lógica de negocio.
 *
 * <pre>
 * POST   /orders                         {"customerId":"c-1"}
 * POST   /orders/{id}/lines              {"productId":"p-1","quantity":2,"unitPrice":9.95}
 * DELETE /orders/{id}/lines/{productId}
 * POST   /orders/{id}/place
 * POST   /orders/{id}/cancel
 * GET    /orders/{id}
 * </pre>
 */
@RestController
@RequestMapping("/orders")
public class OrderController {

	public record CreateOrderRequest(String customerId) {
	}

	public record AddLineRequest(String productId, int quantity, BigDecimal unitPrice) {
	}

	public record LineView(String productId, int quantity, BigDecimal unitPrice, BigDecimal subtotal) {
	}

	public record OrderView(String id, String customerId, String status, List<LineView> lines, BigDecimal total) {

		static OrderView of(Order o) {
			return new OrderView(o.id().value(), o.customerId().value(), o.status().name(),
					o.lines().stream().map(l -> new LineView(l.productId().value(), l.quantity(),
							l.unitPrice().amount(), l.subtotal().amount())).toList(),
					o.total().amount());
		}
	}

	private final OrderService service;

	public OrderController(OrderService service) {
		this.service = service;
	}

	@PostMapping
	public ResponseEntity<OrderView> create(@RequestBody CreateOrderRequest request) {
		OrderId id = service.createOrder(new CustomerId(request.customerId()));
		return ResponseEntity.created(URI.create("/orders/" + id)).body(OrderView.of(service.findOrder(id)));
	}

	@GetMapping("/{id}")
	public OrderView get(@PathVariable String id) {
		return OrderView.of(service.findOrder(new OrderId(id)));
	}

	@PostMapping("/{id}/lines")
	public OrderView addLine(@PathVariable String id, @RequestBody AddLineRequest request) {
		OrderId orderId = new OrderId(id);
		service.addProduct(orderId, new ProductId(request.productId()), request.quantity(),
				new Money(request.unitPrice()));
		return OrderView.of(service.findOrder(orderId));
	}

	@DeleteMapping("/{id}/lines/{productId}")
	public OrderView removeLine(@PathVariable String id, @PathVariable String productId) {
		OrderId orderId = new OrderId(id);
		service.removeProduct(orderId, new ProductId(productId));
		return OrderView.of(service.findOrder(orderId));
	}

	@PostMapping("/{id}/place")
	public OrderView place(@PathVariable String id) {
		OrderId orderId = new OrderId(id);
		service.placeOrder(orderId);
		return OrderView.of(service.findOrder(orderId));
	}

	@PostMapping("/{id}/cancel")
	public OrderView cancel(@PathVariable String id) {
		OrderId orderId = new OrderId(id);
		service.cancelOrder(orderId);
		return OrderView.of(service.findOrder(orderId));
	}

	@ExceptionHandler(OrderNotFoundException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public String notFound(OrderNotFoundException e) {
		return e.getMessage();
	}

	/** Una regla de negocio violada se traduce a 409 Conflict. */
	@ExceptionHandler(DomainException.class)
	@ResponseStatus(HttpStatus.CONFLICT)
	public String businessRuleViolated(DomainException e) {
		return e.getMessage();
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public String badRequest(IllegalArgumentException e) {
		return e.getMessage();
	}
}
