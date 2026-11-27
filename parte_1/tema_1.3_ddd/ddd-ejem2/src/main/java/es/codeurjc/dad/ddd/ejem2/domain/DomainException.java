package es.codeurjc.dad.ddd.ejem2.domain;

/**
 * Se lanza cuando una operación violaría una regla de negocio (invariante).
 */
public class DomainException extends RuntimeException {

	public DomainException(String message) {
		super(message);
	}
}
