package es.codeurjc.dad.obs.ejer1.pagos;

import java.util.concurrent.ThreadLocalRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

/**
 * Servicio de pagos CON EL FALLO del ejercicio y la instrumentación que
 * permite encontrarlo.
 *
 * El fallo: todas las llamadas a los proveedores de pago comparten un cerrojo
 * (como un cliente HTTP con una única conexión, o un método synchronized).
 * El proveedor de AMEX es lento, así que cuando hay pagos con AMEX los pagos
 * con VISA esperan su turno detrás de ellos: TODOS los pagos se vuelven lentos
 * aunque VISA responde rápido.
 *
 * Cómo se ve: en la traza de un pago VISA lento, el span
 * "pagos.provider.call" (provider=visa) dura 40 ms, pero el span
 * "pagos.provider.lock-wait" dura cientos de milisegundos.
 *
 * El arreglo (pagos.fix-contention=true): no compartir el cerrojo; en la
 * práctica, un pool de conexiones o un bulkhead por proveedor.
 */
@Service
public class PaymentService {

	public record PaymentResult(String orderId, boolean accepted) {
	}

	private static final Logger log = LoggerFactory.getLogger(PaymentService.class);

	private final ObservationRegistry observations;
	private final boolean fixContention;
	private final Object providerLock = new Object();

	public PaymentService(ObservationRegistry observations, @Value("${pagos.fix-contention}") boolean fixContention) {
		this.observations = observations;
		this.fixContention = fixContention;
	}

	public PaymentResult pay(String orderId, String card, double amount) {
		boolean fraud = Observation.createNotStarted("pagos.fraud.check", observations)
				.observe(() -> {
					sleep(15);
					return amount > 5_000;
				});
		if (fraud) {
			log.atWarn().addKeyValue("orderId", orderId).log("Pago rechazado por sospecha de fraude");
			return new PaymentResult(orderId, false);
		}
		String provider = "amex".equalsIgnoreCase(card) ? "amex" : "visa";
		boolean accepted = fixContention ? callProvider(provider) : callProviderWithSharedLock(provider);
		log.atInfo().addKeyValue("orderId", orderId).addKeyValue("provider", provider)
				.addKeyValue("accepted", accepted).log("Pago procesado");
		return new PaymentResult(orderId, accepted);
	}

	/** EL FALLO: un único cerrojo para todos los proveedores. */
	private boolean callProviderWithSharedLock(String provider) {
		Observation wait = Observation.createNotStarted("pagos.provider.lock-wait", observations)
				.lowCardinalityKeyValue("provider", provider)
				.start();
		synchronized (providerLock) {
			wait.stop(); // el span mide cuánto se ha esperado para entrar
			return callProvider(provider);
		}
	}

	private boolean callProvider(String provider) {
		return Observation.createNotStarted("pagos.provider.call", observations)
				.lowCardinalityKeyValue("provider", provider)
				.observe(() -> {
					sleep(provider.equals("amex") ? 300 + ThreadLocalRandom.current().nextInt(200) : 40);
					return ThreadLocalRandom.current().nextInt(100) >= 3;
				});
	}

	private static void sleep(long ms) {
		try {
			Thread.sleep(ms);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}
}
