package es.codeurjc.dad.eventos.ejem3.facturacion;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Consumidor IDEMPOTENTE: procesar el mismo mensaje dos veces tiene el mismo
 * efecto que procesarlo una vez.
 *
 * El registro del mensaje procesado y la factura se guardan en la MISMA
 * transacción: o se hacen las dos cosas o ninguna. Si dos copias del mensaje
 * llegasen a la vez, la clave primaria de ProcessedMessage haría fallar a una
 * de ellas.
 */
@Service
public class InvoiceService {

	private static final Logger log = LoggerFactory.getLogger(InvoiceService.class);

	private final InvoiceRepository invoices;
	private final ProcessedMessageRepository processed;

	public InvoiceService(InvoiceRepository invoices, ProcessedMessageRepository processed) {
		this.invoices = invoices;
		this.processed = processed;
	}

	/** @return true si se ha generado la factura, false si era un duplicado */
	@Transactional
	public boolean handle(String messageId, OrderPlaced event) {
		if (processed.existsById(messageId)) {
			log.warn("Mensaje {} duplicado: se ignora (pedido {})", messageId, event.orderId());
			return false;
		}
		invoices.save(new Invoice(event.orderId(), event.customer(), event.amount()));
		processed.save(new ProcessedMessage(messageId, Instant.now()));
		log.info("Factura generada para el pedido {} ({} €)", event.orderId(), event.amount());
		return true;
	}
}
