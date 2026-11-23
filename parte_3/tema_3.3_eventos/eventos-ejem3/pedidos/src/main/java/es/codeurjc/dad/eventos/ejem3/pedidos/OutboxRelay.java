package es.codeurjc.dad.eventos.ejem3.pedidos;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageBuilder;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Message relay (polling publisher): lee periódicamente la tabla outbox y
 * publica en RabbitMQ los mensajes pendientes.
 *
 * Garantía: AL MENOS UNA VEZ. Si la aplicación se cae después de publicar y
 * antes de marcar el mensaje como publicado, se volverá a enviar. Por eso el
 * consumidor tiene que ser IDEMPOTENTE (ver proyecto facturacion).
 *
 * Alternativa al polling: Change Data Capture (p. ej. Debezium leyendo el log
 * de transacciones de la base de datos).
 */
@Component
public class OutboxRelay {

	private static final Logger log = LoggerFactory.getLogger(OutboxRelay.class);

	private final OutboxRepository outbox;
	private final RabbitTemplate rabbit;

	public OutboxRelay(OutboxRepository outbox, RabbitTemplate rabbit) {
		this.outbox = outbox;
		this.rabbit = rabbit;
	}

	@Scheduled(fixedDelayString = "${outbox.relay.delay}")
	@Transactional
	public void publishPending() {
		List<OutboxMessage> pending = outbox.findTop50ByPublishedAtIsNullOrderByCreatedAtAsc();
		for (OutboxMessage m : pending) {
			Message message = MessageBuilder.withBody(m.getPayload().getBytes(StandardCharsets.UTF_8))
					.setContentType(MessageProperties.CONTENT_TYPE_JSON)
					.setMessageId(m.getId()) // el consumidor lo usará para detectar duplicados
					.build();
			rabbit.send(Application.EXCHANGE, m.getRoutingKey(), message);
			m.markPublished(Instant.now());
			log.info("Publicado {} ({}) del pedido {}", m.getRoutingKey(), m.getId(), m.getAggregateId());
		}
	}
}
