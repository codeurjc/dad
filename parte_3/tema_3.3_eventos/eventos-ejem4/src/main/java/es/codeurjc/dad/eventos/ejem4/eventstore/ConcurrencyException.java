package es.codeurjc.dad.eventos.ejem4.eventstore;

public class ConcurrencyException extends RuntimeException {

	public ConcurrencyException(String streamId, int expected, int actual) {
		super("Conflicto en " + streamId + ": se esperaba la versión " + expected + " pero es la " + actual);
	}
}
