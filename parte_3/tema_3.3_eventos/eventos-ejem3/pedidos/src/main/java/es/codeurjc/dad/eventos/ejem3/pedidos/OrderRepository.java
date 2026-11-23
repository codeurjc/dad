package es.codeurjc.dad.eventos.ejem3.pedidos;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderRepository extends JpaRepository<Order, String> {
}
