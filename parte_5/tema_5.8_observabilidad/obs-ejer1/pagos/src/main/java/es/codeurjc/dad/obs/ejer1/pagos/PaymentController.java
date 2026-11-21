package es.codeurjc.dad.obs.ejer1.pagos;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PaymentController {

	public record PaymentRequest(String orderId, String card, double amount) {
	}

	private final PaymentService payments;

	public PaymentController(PaymentService payments) {
		this.payments = payments;
	}

	@PostMapping("/payments")
	public PaymentService.PaymentResult pay(@RequestBody PaymentRequest request) {
		return payments.pay(request.orderId(), request.card(), request.amount());
	}
}
