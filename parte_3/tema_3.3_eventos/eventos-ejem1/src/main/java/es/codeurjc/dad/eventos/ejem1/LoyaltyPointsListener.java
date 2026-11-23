package es.codeurjc.dad.eventos.ejem1;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * @Async + @TransactionalEventListener: tras el commit, el evento se procesa en
 * OTRO hilo. El que hizo el pedido no espera a que se calculen los puntos.
 *
 * Es asíncrono pero sigue siendo en memoria: si la aplicación se cae antes de
 * procesarlo, el evento se pierde. Para eso necesitaremos un broker (ejemplo 2)
 * y el patrón outbox (ejemplo 3).
 */
@Component
public class LoyaltyPointsListener {

	private static final Logger log = LoggerFactory.getLogger(LoyaltyPointsListener.class);

	private final EventLog eventLog;

	public LoyaltyPointsListener(EventLog eventLog) {
		this.eventLog = eventLog;
	}

	@Async
	@TransactionalEventListener
	public void on(OrderPlaced event) throws InterruptedException {
		Thread.sleep(500); // un cálculo "lento"
		int points = event.total().intValue() / 10;
		log.info("[{}] Sumando {} puntos de fidelidad a {}", Thread.currentThread().getName(), points,
				event.customerEmail());
		eventLog.add("puntos:" + event.orderId());
	}
}
