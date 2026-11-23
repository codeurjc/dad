package es.codeurjc.dad.micro.ejer1.libros;

import org.springframework.data.jpa.repository.JpaRepository;

public interface BookRepository extends JpaRepository<Book, String> {
}
