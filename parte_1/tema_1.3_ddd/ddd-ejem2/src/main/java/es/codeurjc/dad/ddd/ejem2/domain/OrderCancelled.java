package es.codeurjc.dad.ddd.ejem2.domain;

import java.time.Instant;

public record OrderCancelled(OrderId orderId, CustomerId customerId, Instant occurredOn) implements DomainEvent {
}
