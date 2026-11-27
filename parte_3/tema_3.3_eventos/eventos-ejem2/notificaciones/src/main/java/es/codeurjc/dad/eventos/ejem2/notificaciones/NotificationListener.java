package es.codeurjc.dad.eventos.ejem2.notificaciones;

import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Component
public class NotificationListener {

	private static final Logger log = LoggerFactory.getLogger(NotificationListener.class);

	@RabbitListener(queues = Application.QUEUE_EMAILS)
	public void onOrderPlaced(OrderPlaced event) {
		log.info("Enviando email a {}: tu pedido {} por {} € está confirmado", event.customerEmail(),
				event.orderId(), event.total());
	}

	/**
	 * Recibe el mensaje "en crudo" (sin convertir), sea del tipo que sea.
	 */
	@RabbitListener(queues = Application.QUEUE_AUDIT)
	public void audit(Message message) {
		log.info("[auditoría] {} -> {}", message.getMessageProperties().getReceivedRoutingKey(),
				new String(message.getBody(), StandardCharsets.UTF_8));
	}
}
