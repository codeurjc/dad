package es.codeurjc.dad.ddd.ejer1.infrastructure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import es.codeurjc.dad.ddd.ejer1.domain.DomainEvent;

@Component
public class LibraryEventsLogger {

	private static final Logger log = LoggerFactory.getLogger(LibraryEventsLogger.class);

	@EventListener
	public void on(DomainEvent event) {
		switch (event) {
			case DomainEvent.CopyBorrowed e -> log.info("{} se lleva {} hasta el {}", e.memberId(), e.copyId(), e.dueDate());
			case DomainEvent.LoanRenewed e -> log.info("{} renueva {} hasta el {}", e.memberId(), e.copyId(), e.newDueDate());
			case DomainEvent.CopyReturned e -> log.info("{} devuelve {} ({} días de retraso)", e.memberId(), e.copyId(), e.daysLate());
			case DomainEvent.PenaltyImposed e -> log.info("{} recibe una penalización de {}", e.memberId(), e.amount());
		}
	}
}
