package es.codeurjc.dad.ddd.ejem2.infrastructure.events;

import java.util.List;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import es.codeurjc.dad.ddd.ejem2.application.DomainEventPublisher;
import es.codeurjc.dad.ddd.ejem2.domain.DomainEvent;

/**
 * Adaptador: publica los eventos de dominio usando el bus de eventos en memoria
 * de Spring. En el tema 3 veremos cómo publicarlos en un broker de mensajes.
 */
@Component
public class SpringDomainEventPublisher implements DomainEventPublisher {

	private final ApplicationEventPublisher publisher;

	public SpringDomainEventPublisher(ApplicationEventPublisher publisher) {
		this.publisher = publisher;
	}

	@Override
	public void publish(List<DomainEvent> events) {
		events.forEach(publisher::publishEvent);
	}
}
