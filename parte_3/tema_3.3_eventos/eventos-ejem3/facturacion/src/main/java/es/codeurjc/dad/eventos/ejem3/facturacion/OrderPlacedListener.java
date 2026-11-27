package es.codeurjc.dad.eventos.ejem3.facturacion;

import org.springframework.amqp.AmqpRejectAndDontRequeueException;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.support.AmqpHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;

@Component
public class OrderPlacedListener {

	private final InvoiceService invoices;

	public OrderPlacedListener(InvoiceService invoices) {
		this.invoices = invoices;
	}

	@RabbitListener(queues = Application.QUEUE)
	public void on(OrderPlaced event, @Header(name = AmqpHeaders.MESSAGE_ID, required = false) String messageId) {
		if (messageId == null) {
			// Sin identificador no podemos garantizar la idempotencia
			throw new AmqpRejectAndDontRequeueException("Mensaje sin message-id");
		}
		invoices.handle(messageId, event);
	}
}
