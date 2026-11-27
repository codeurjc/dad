package es.codeurjc.dad.eventos.ejem3.pedidos;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OutboxRepository extends JpaRepository<OutboxMessage, String> {

	List<OutboxMessage> findTop50ByPublishedAtIsNullOrderByCreatedAtAsc();

	long countByPublishedAtIsNull();
}
