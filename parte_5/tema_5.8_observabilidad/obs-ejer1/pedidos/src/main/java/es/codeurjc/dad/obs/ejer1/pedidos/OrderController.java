package es.codeurjc.dad.obs.ejer1.pedidos;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * <pre>
 * curl -X POST localhost:8080/orders -H 'Content-Type: application/json' -d '{"card":"visa","amount":30}'
 * </pre>
 */
@RestController
public class OrderController {

	public record OrderRequest(String card, double amount) {
	}

	public record PaymentRequest(String orderId, String card, double amount) {
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record PaymentResult(String orderId, boolean accepted) {
	}

	private static final Logger log = LoggerFactory.getLogger(OrderController.class);

	private final RestClient pagos;
	private final MeterRegistry metrics;

	public OrderController(RestClient pagosClient, MeterRegistry metrics) {
		this.pagos = pagosClient;
		this.metrics = metrics;
	}

	@PostMapping("/orders")
	public PaymentResult order(@RequestBody OrderRequest request) {
		String orderId = UUID.randomUUID().toString();
		log.atInfo().addKeyValue("orderId", orderId).addKeyValue("card", request.card()).log("Nuevo pedido");

		PaymentResult result = pagos.post().uri("/payments")
				.body(new PaymentRequest(orderId, request.card(), request.amount()))
				.retrieve().body(PaymentResult.class);

		// Etiqueta de baja cardinalidad: resultado (2 valores). NUNCA el orderId.
		metrics.counter("pedidos.orders", "result", result.accepted() ? "accepted" : "rejected").increment();
		return result;
	}
}
