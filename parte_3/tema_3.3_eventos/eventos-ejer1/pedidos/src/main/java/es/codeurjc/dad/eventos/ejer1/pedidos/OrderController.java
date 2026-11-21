package es.codeurjc.dad.eventos.ejer1.pedidos;

import java.math.BigDecimal;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * <pre>
 * curl -X POST localhost:8080/orders -H 'Content-Type: application/json' \
 *   -d '{"customerId":"ana","productId":"libro-ddd","quantity":1,"amount":45}'
 * curl localhost:8080/orders/{orderId}
 * </pre>
 */
@RestController
public class OrderController {

	public record CreateOrderRequest(String customerId, String productId, int quantity, BigDecimal amount) {
	}

	public record OrderView(String id, String customerId, String productId, int quantity, BigDecimal amount,
			OrderStatus status, String rejectionReason) {

		static OrderView of(Order o) {
			return new OrderView(o.id(), o.customerId(), o.productId(), o.quantity(), o.amount(), o.status(),
					o.rejectionReason());
		}
	}

	private final OrderService orders;

	public OrderController(OrderService orders) {
		this.orders = orders;
	}

	/** 202 Accepted: el pedido se ha aceptado para procesarlo, pero aún no está aprobado. */
	@PostMapping("/orders")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public OrderView create(@RequestBody CreateOrderRequest r) {
		return OrderView.of(orders.createOrder(r.customerId(), r.productId(), r.quantity(), r.amount()));
	}

	@GetMapping("/orders/{orderId}")
	public ResponseEntity<OrderView> get(@PathVariable String orderId) {
		return orders.find(orderId).map(o -> ResponseEntity.ok(OrderView.of(o)))
				.orElseGet(() -> ResponseEntity.notFound().build());
	}
}
