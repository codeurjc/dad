package es.codeurjc.dad.eventos.ejem2.pedidos;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import es.codeurjc.dad.eventos.ejem2.pedidos.Events.Line;
import es.codeurjc.dad.eventos.ejem2.pedidos.Events.OrderCancelled;
import es.codeurjc.dad.eventos.ejem2.pedidos.Events.OrderPlaced;

/**
 * <pre>
 * curl -X POST localhost:8080/orders -H 'Content-Type: application/json' \
 *   -d '{"email":"ana@urjc.es","lines":[{"product":"libro-ddd","quantity":2,"unitPrice":45.5}]}'
 * curl -X POST localhost:8080/orders/{orderId}/cancel
 * </pre>
 */
@RestController
public class OrderController {

	public record PlaceOrderRequest(String email, List<Line> lines) {
	}

	private final OrderPublisher orders;

	public OrderController(OrderPublisher orders) {
		this.orders = orders;
	}

	@PostMapping("/orders")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public OrderPlaced place(@RequestBody PlaceOrderRequest request) {
		return orders.placeOrder(request.email(), request.lines());
	}

	@PostMapping("/orders/{orderId}/cancel")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public OrderCancelled cancel(@PathVariable String orderId) {
		return orders.cancelOrder(orderId);
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public String notFound(IllegalArgumentException e) {
		return e.getMessage();
	}
}
