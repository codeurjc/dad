package es.codeurjc.dad.balanceo.ejer1.lb;

public class NoHealthyBackendException extends RuntimeException {

	public NoHealthyBackendException() {
		super("No hay ningún servidor disponible");
	}
}
