package es.codeurjc.dad.obs.ejem1;

import java.util.concurrent.ThreadLocalRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * <pre>
 * curl -i -X POST "localhost:8080/checkout?user=ana&amp;amount=120"
 * curl -i -X POST "localhost:8080/checkout?user=ana&amp;amount=120" -H "X-Correlation-Id: prueba-1"
 * </pre>
 */
@RestController
public class CheckoutController {

	public record Receipt(String orderId, String user, double amount) {
	}

	private static final Logger log = LoggerFactory.getLogger(CheckoutController.class);

	@PostMapping("/checkout")
	public Receipt checkout(@RequestParam String user, @RequestParam double amount) {
		// ✘ Mal: el dato está "enterrado" en el texto; para buscar por usuario hay que usar regex
		// log.info("El usuario " + user + " compra por " + amount + " euros");

		// ✔ Bien: mensaje fijo + pares clave-valor -> campos JSON por los que se puede filtrar
		log.atInfo().addKeyValue("user", user).addKeyValue("amount", amount).log("Inicio de compra");

		if (amount <= 0) {
			throw new IllegalArgumentException("Importe no válido: " + amount);
		}
		String orderId = "P-" + ThreadLocalRandom.current().nextInt(100_000);
		boolean paymentOk = ThreadLocalRandom.current().nextInt(10) > 0;
		if (!paymentOk) {
			log.atWarn().addKeyValue("orderId", orderId).addKeyValue("reason", "fondos_insuficientes")
					.log("Pago rechazado");
			throw new IllegalStateException("Pago rechazado");
		}
		log.atInfo().addKeyValue("orderId", orderId).addKeyValue("amount", amount).log("Compra completada");
		return new Receipt(orderId, user, amount);
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public String badRequest(IllegalArgumentException e) {
		log.atWarn().setCause(e).log("Petición no válida");
		return e.getMessage();
	}

	@ExceptionHandler(IllegalStateException.class)
	@ResponseStatus(HttpStatus.PAYMENT_REQUIRED)
	public String rejected(IllegalStateException e) {
		return e.getMessage();
	}
}
