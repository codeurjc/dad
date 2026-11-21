package es.codeurjc.dad.micro.ejem1.pedidos;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * <pre>
 * curl -X POST localhost:8082/orders -H 'Content-Type: application/json' -d '{"productId":1,"quantity":2}'
 * curl localhost:8082/orders
 * </pre>
 */
@RestController
@RequestMapping("/orders")
public class OrderController {

	public record PlaceOrderRequest(Long productId, int quantity) {
	}

	private final OrderService service;
	private final OrderRepository orders;

	public OrderController(OrderService service, OrderRepository orders) {
		this.service = service;
		this.orders = orders;
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public Order place(@RequestBody PlaceOrderRequest request) {
		return service.placeOrder(request.productId(), request.quantity());
	}

	@GetMapping
	public List<Order> all() {
		return orders.findAll();
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public String notFound(IllegalArgumentException e) {
		return e.getMessage();
	}

	@ExceptionHandler(IllegalStateException.class)
	@ResponseStatus(HttpStatus.CONFLICT)
	public String conflict(IllegalStateException e) {
		return e.getMessage();
	}
}
