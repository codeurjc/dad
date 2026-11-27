package es.codeurjc.dad.ddd.ejem2.domain;

import java.util.Optional;

/**
 * Repositorio (puerto de salida en arquitectura hexagonal).
 *
 * <ul>
 * <li>Hay un repositorio por agregado, no por tabla: no existe un
 * OrderLineRepository porque las líneas solo se acceden a través de Order.</li>
 * <li>Su interfaz está en el dominio y habla el lenguaje del dominio.</li>
 * <li>La implementación (JPA, memoria, Mongo...) está en infraestructura.</li>
 * </ul>
 */
public interface OrderRepository {

	OrderId nextId();

	Optional<Order> findById(OrderId id);

	void save(Order order);
}
