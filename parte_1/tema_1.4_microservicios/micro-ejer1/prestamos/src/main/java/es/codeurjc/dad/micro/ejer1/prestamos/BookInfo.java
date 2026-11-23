package es.codeurjc.dad.micro.ejer1.prestamos;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Lo que Préstamos necesita saber de un libro (su propia vista). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BookInfo(String isbn, String title, int availableCopies) {
}
