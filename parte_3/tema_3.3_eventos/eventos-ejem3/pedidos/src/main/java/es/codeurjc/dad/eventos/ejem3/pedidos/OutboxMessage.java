package es.codeurjc.dad.eventos.ejem3.pedidos;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

/**
 * Fila de la tabla OUTBOX: un mensaje pendiente de publicar.
 *
 * Se guarda en la MISMA base de datos y en la MISMA transacción que el cambio
 * de negocio (el pedido). O se guardan los dos o ninguno.
 */
@Entity
public class OutboxMessage {

	/** Identificador único del evento: el consumidor lo usará para detectar duplicados. */
	@Id
	private String id;

	private String aggregateId;

	private String routingKey;

	@Column(length = 4000)
	private String payload;

	private Instant createdAt;

	/** null mientras no se haya publicado en el broker. */
	private Instant publishedAt;

	protected OutboxMessage() {
	}

	public OutboxMessage(String id, String aggregateId, String routingKey, String payload, Instant createdAt) {
		this.id = id;
		this.aggregateId = aggregateId;
		this.routingKey = routingKey;
		this.payload = payload;
		this.createdAt = createdAt;
	}

	public void markPublished(Instant when) {
		this.publishedAt = when;
	}

	public String getId() {
		return id;
	}

	public String getAggregateId() {
		return aggregateId;
	}

	public String getRoutingKey() {
		return routingKey;
	}

	public String getPayload() {
		return payload;
	}

	public Instant getCreatedAt() {
		return createdAt;
	}

	public Instant getPublishedAt() {
		return publishedAt;
	}
}
