package es.codeurjc.dad.ddd.ejem2.application;

import java.util.List;

import es.codeurjc.dad.ddd.ejem2.domain.DomainEvent;

/**
 * Puerto de salida para publicar eventos de dominio. La aplicación no sabe si
 * se publican en memoria, en RabbitMQ o en Kafka.
 */
public interface DomainEventPublisher {

	void publish(List<DomainEvent> events);
}
