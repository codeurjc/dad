package es.codeurjc.dad.micro.ejem1.pedidos;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderRepository extends JpaRepository<Order, Long> {
}
