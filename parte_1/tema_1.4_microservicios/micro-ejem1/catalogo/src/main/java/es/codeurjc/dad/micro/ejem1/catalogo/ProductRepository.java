package es.codeurjc.dad.micro.ejem1.catalogo;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long> {
}
