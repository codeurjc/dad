package es.codeurjc.dad.obs.ejer1.pagos;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Test;

import io.micrometer.observation.ObservationRegistry;

class PaymentServiceTest {

	@Test
	void losPagosSospechososSeRechazan() {
		PaymentService service = new PaymentService(ObservationRegistry.NOOP, true);
		assertFalse(service.pay("p1", "visa", 10_000).accepted());
	}

	@Test
	void conElArregloUnPagoVisaNoEsperaAUnoAmex() throws Exception {
		PaymentService service = new PaymentService(ObservationRegistry.NOOP, true);

		CompletableFuture<?> amex = CompletableFuture.runAsync(() -> service.pay("a", "amex", 10));
		Thread.sleep(50); // el pago AMEX ya está en el proveedor
		long start = System.nanoTime();
		service.pay("v", "visa", 10);
		long millis = (System.nanoTime() - start) / 1_000_000;
		amex.join();

		assertTrue(millis < 250, "VISA tarda " + millis + " ms: no debería esperar a AMEX");
	}

	@Test
	void conElFalloUnPagoVisaEsperaAUnoAmex() throws Exception {
		PaymentService service = new PaymentService(ObservationRegistry.NOOP, false);

		CompletableFuture<?> amex = CompletableFuture.runAsync(() -> service.pay("a", "amex", 10));
		Thread.sleep(50);
		long start = System.nanoTime();
		service.pay("v", "visa", 10);
		long millis = (System.nanoTime() - start) / 1_000_000;
		amex.join();

		assertTrue(millis >= 250, "VISA tarda " + millis + " ms: ha esperado al cerrojo");
	}
}
