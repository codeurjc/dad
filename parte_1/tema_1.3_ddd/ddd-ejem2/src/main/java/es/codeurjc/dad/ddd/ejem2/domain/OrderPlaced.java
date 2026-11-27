package es.codeurjc.dad.ddd.ejem2.domain;

import java.time.Instant;

public record OrderPlaced(OrderId orderId, CustomerId customerId, Money total, int units, Instant occurredOn)
		implements DomainEvent {
}
