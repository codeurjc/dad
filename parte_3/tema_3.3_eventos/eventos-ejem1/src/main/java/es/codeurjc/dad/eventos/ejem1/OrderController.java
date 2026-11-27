package es.codeurjc.dad.eventos.ejem1;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * <pre>
 * POST /orders {"email":"ana@urjc.es","total":120}
 * POST /orders {"email":"ana@urjc.es","total":20000}   ← falla: mira el log
 * GET  /log
 * </pre>
 */
@RestController
public class OrderController {

	public record PlaceOrderRequest(String email, BigDecimal total) {
	}

	public record PlaceOrderResponse(Long orderId) {
	}

	private final OrderService service;
	private final EventLog eventLog;

	public OrderController(OrderService service, EventLog eventLog) {
		this.service = service;
		this.eventLog = eventLog;
	}

	@PostMapping("/orders")
	@ResponseStatus(HttpStatus.CREATED)
	public PlaceOrderResponse place(@RequestBody PlaceOrderRequest request) {
		return new PlaceOrderResponse(service.placeOrder(request.email(), request.total()));
	}

	@GetMapping("/log")
	public List<String> log() {
		return eventLog.entries();
	}

	@ExceptionHandler(IllegalStateException.class)
	@ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
	public String rejected(IllegalStateException e) {
		return e.getMessage();
	}
}
