package es.codeurjc.dad.obs.ejem2;

import java.util.concurrent.ThreadLocalRandom;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Simula una tienda: la pasarela de pago tarda entre 20 y 200 ms y, a veces,
 * mucho más; un 5 % de los pagos fallan.
 *
 * <pre>
 * curl -X POST "localhost:8080/orders?payment=card&amp;amount=35.5"
 * curl localhost:8080/actuator/prometheus | grep shop_
 * </pre>
 */
@RestController
public class ShopController {

	public record OrderResult(String orderId, String payment, double amount) {
	}

	private final ShopMetrics metrics;

	public ShopController(ShopMetrics metrics) {
		this.metrics = metrics;
	}

	@PostMapping("/orders")
	public OrderResult order(@RequestParam(defaultValue = "card") String payment, @RequestParam double amount) {
		if (!payment.equals("card") && !payment.equals("paypal") && !payment.equals("transfer")) {
			// Validar el valor de la etiqueta evita que un cliente cree series nuevas a voluntad
			throw new IllegalArgumentException("Método de pago no soportado");
		}
		metrics.cartOpened();
		try {
			boolean paid = metrics.paymentTimer().record(this::callPaymentGateway);
			if (!paid) {
				metrics.orderFailed(payment, "rejected");
				throw new PaymentRejectedException();
			}
			metrics.orderPlaced(payment, amount);
			return new OrderResult("P-" + ThreadLocalRandom.current().nextInt(1_000_000), payment, amount);
		} finally {
			metrics.cartClosed();
		}
	}

	private boolean callPaymentGateway() {
		ThreadLocalRandom random = ThreadLocalRandom.current();
		long latency = random.nextInt(100) < 3 ? 1_500 : 20 + random.nextInt(180); // 3 % muy lentos
		try {
			Thread.sleep(latency);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		return random.nextInt(100) >= 5;
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public String badRequest(IllegalArgumentException e) {
		return e.getMessage();
	}

	@ExceptionHandler(PaymentRejectedException.class)
	@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
	public String rejected(PaymentRejectedException e) {
		return e.getMessage();
	}

	static class PaymentRejectedException extends RuntimeException {

		PaymentRejectedException() {
			super("La pasarela de pago ha rechazado el cobro");
		}
	}
}
