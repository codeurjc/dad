package es.codeurjc.dad.eventos.ejer1.stock;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import es.codeurjc.dad.eventos.ejer1.stock.Events.OrderCreated;
import es.codeurjc.dad.eventos.ejer1.stock.Events.PaymentRejected;
import es.codeurjc.dad.eventos.ejer1.stock.Events.StockRejected;
import es.codeurjc.dad.eventos.ejer1.stock.Events.StockReserved;

@Service
public class StockService {

	private static final Logger log = LoggerFactory.getLogger(StockService.class);

	private final RabbitTemplate rabbit;
	private final Warehouse warehouse = new Warehouse(Map.of("libro-ddd", 10, "libro-eda", 2, "taza", 100));

	public StockService(RabbitTemplate rabbit) {
		this.rabbit = rabbit;
	}

	@RabbitListener(queues = Application.Q_ORDER_CREATED)
	public void on(OrderCreated event) {
		if (warehouse.reserve(event.orderId(), event.productId(), event.quantity())) {
			log.info("Pedido {}: reservadas {} uds. de {} (quedan {})", event.orderId(), event.quantity(),
					event.productId(), warehouse.available(event.productId()));
			rabbit.convertAndSend(Application.EXCHANGE, "stock.reservado",
					new StockReserved(event.orderId(), event.customerId(), event.amount()));
		} else {
			log.info("Pedido {}: no hay stock de {}", event.orderId(), event.productId());
			rabbit.convertAndSend(Application.EXCHANGE, "stock.rechazado",
					new StockRejected(event.orderId(), "no quedan " + event.quantity() + " uds. de " + event.productId()));
		}
	}

	/** Compensación: si el pago falla, devolvemos las unidades reservadas. */
	@RabbitListener(queues = Application.Q_PAYMENT_REJECTED)
	public void on(PaymentRejected event) {
		if (warehouse.release(event.orderId())) {
			log.info("Pedido {}: reserva liberada (compensación)", event.orderId());
		}
	}

	public Warehouse warehouse() {
		return warehouse;
	}
}
