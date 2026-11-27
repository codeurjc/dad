package es.codeurjc.dad.eventos.ejer1.pagos;

import java.math.BigDecimal;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import es.codeurjc.dad.eventos.ejer1.pagos.Events.PaymentAccepted;
import es.codeurjc.dad.eventos.ejer1.pagos.Events.PaymentRejected;
import es.codeurjc.dad.eventos.ejer1.pagos.Events.StockReserved;
import es.codeurjc.dad.eventos.ejer1.pagos.Wallets.ChargeResult;

@Service
public class PaymentService {

	private static final Logger log = LoggerFactory.getLogger(PaymentService.class);

	private final RabbitTemplate rabbit;
	private final Wallets wallets = new Wallets(Map.of(
			"ana", new BigDecimal("500"),
			"luis", new BigDecimal("20")));

	public PaymentService(RabbitTemplate rabbit) {
		this.rabbit = rabbit;
	}

	@RabbitListener(queues = Application.Q_STOCK_RESERVED)
	public void on(StockReserved event) {
		ChargeResult result = wallets.charge(event.orderId(), event.customerId(), event.amount());
		if (result.accepted()) {
			log.info("Pedido {}: cobrados {} € a {}", event.orderId(), event.amount(), event.customerId());
			rabbit.convertAndSend(Application.EXCHANGE, "pago.aceptado", new PaymentAccepted(event.orderId()));
		} else {
			log.info("Pedido {}: pago rechazado ({})", event.orderId(), result.reason());
			rabbit.convertAndSend(Application.EXCHANGE, "pago.rechazado",
					new PaymentRejected(event.orderId(), result.reason()));
		}
	}

	public Wallets wallets() {
		return wallets;
	}
}
