package es.codeurjc.dad.fund.ejem2;

/** Un valor con su versión. Gana la versión más alta (last-writer-wins). */
public record Versioned(String value, long version) {
}
