package es.codeurjc.dad.eventos.ejem1;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * @TransactionalEventListener(AFTER_COMMIT): el evento se entrega SOLO si la
 * transacción del publicador termina con éxito. Ideal para efectos externos
 * (emails, mensajes a otros servicios) que no deben ocurrir si hay rollback.
 */
@Component
public class EmailListener {

	private static final Logger log = LoggerFactory.getLogger(EmailListener.class);

	private final EventLog eventLog;

	public EmailListener(EventLog eventLog) {
		this.eventLog = eventLog;
	}

	@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
	public void on(OrderPlaced event) {
		log.info("[{}] Enviando email de confirmación a {}", Thread.currentThread().getName(), event.customerEmail());
		eventLog.add("email:" + event.orderId());
	}
}
