package es.codeurjc.dad.eventos.ejem2.inventario;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import es.codeurjc.dad.eventos.ejem2.inventario.Events.Line;
import es.codeurjc.dad.eventos.ejem2.inventario.Events.OrderCancelled;
import es.codeurjc.dad.eventos.ejem2.inventario.Events.OrderPlaced;

@Component
public class InventoryListener {

	private static final Logger log = LoggerFactory.getLogger(InventoryListener.class);

	private final Stock stock = new Stock(Map.of("libro-ddd", 20, "libro-eda", 8, "taza", 50));

	@RabbitListener(queues = Application.QUEUE_PLACED)
	public void on(OrderPlaced event) {
		for (Line line : event.lines()) {
			stock.remove(line.product(), line.quantity());
			log.info("Pedido {}: -{} {} (quedan {})", event.orderId(), line.quantity(), line.product(),
					stock.unitsOf(line.product()));
			if (stock.needsRestock(line.product())) {
				log.warn("Hay que reponer {}", line.product());
			}
		}
	}

	@RabbitListener(queues = Application.QUEUE_CANCELLED)
	public void on(OrderCancelled event) {
		for (Line line : event.lines()) {
			stock.add(line.product(), line.quantity());
			log.info("Pedido {} cancelado: +{} {} (quedan {})", event.orderId(), line.quantity(), line.product(),
					stock.unitsOf(line.product()));
		}
	}

	public Stock stock() {
		return stock;
	}
}
