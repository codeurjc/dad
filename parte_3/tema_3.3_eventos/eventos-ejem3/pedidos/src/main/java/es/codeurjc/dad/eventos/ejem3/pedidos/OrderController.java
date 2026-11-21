package es.codeurjc.dad.eventos.ejem3.pedidos;

import java.math.BigDecimal;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * <pre>
 * curl -X POST localhost:8080/orders -H 'Content-Type: application/json' -d '{"customer":"ana","amount":99.90}'
 * curl localhost:8080/outbox/pending
 * </pre>
 */
@RestController
public class OrderController {

	public record PlaceOrderRequest(String customer, BigDecimal amount) {
	}

	public record PlaceOrderResponse(String orderId) {
	}

	private final OrderService service;
	private final OutboxRepository outbox;

	public OrderController(OrderService service, OutboxRepository outbox) {
		this.service = service;
		this.outbox = outbox;
	}

	@PostMapping("/orders")
	@ResponseStatus(HttpStatus.CREATED)
	public PlaceOrderResponse place(@RequestBody PlaceOrderRequest request) {
		return new PlaceOrderResponse(service.placeOrder(request.customer(), request.amount()));
	}

	@GetMapping("/outbox/pending")
	public long pending() {
		return outbox.countByPublishedAtIsNull();
	}
}
