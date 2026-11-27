package es.codeurjc.dad.eventos.ejem3.facturacion;

import java.time.Instant;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

/**
 * Registro de los mensajes ya procesados (tabla "inbox" o de deduplicación).
 */
@Entity
public class ProcessedMessage {

	@Id
	private String messageId;

	private Instant processedAt;

	protected ProcessedMessage() {
	}

	public ProcessedMessage(String messageId, Instant processedAt) {
		this.messageId = messageId;
		this.processedAt = processedAt;
	}

	public String getMessageId() {
		return messageId;
	}

	public Instant getProcessedAt() {
		return processedAt;
	}
}
