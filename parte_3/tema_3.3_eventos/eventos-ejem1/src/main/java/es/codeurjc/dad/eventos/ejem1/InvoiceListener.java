package es.codeurjc.dad.eventos.ejem1;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * @EventListener: se ejecuta de forma SÍNCRONA, en el mismo hilo y DENTRO de la
 * transacción del publicador, en el momento en que se publica el evento.
 *
 * Si la transacción falla después, este listener ya se ha ejecutado. Si lo que
 * hace no es transaccional (enviar un email, llamar a una API...), no se puede
 * deshacer.
 */
@Component
public class InvoiceListener {

	private static final Logger log = LoggerFactory.getLogger(InvoiceListener.class);

	private final EventLog eventLog;

	public InvoiceListener(EventLog eventLog) {
		this.eventLog = eventLog;
	}

	@EventListener
	public void on(OrderPlaced event) {
		log.info("[{}] Generando factura del pedido {} por {} €", Thread.currentThread().getName(),
				event.orderId(), event.total());
		eventLog.add("factura:" + event.orderId());
	}
}
