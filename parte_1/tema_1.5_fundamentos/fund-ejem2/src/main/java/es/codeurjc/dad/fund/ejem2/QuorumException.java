package es.codeurjc.dad.fund.ejem2;

public class QuorumException extends RuntimeException {

	public QuorumException(String operation, int needed, int available) {
		super("No hay quórum para " + operation + ": hacen falta " + needed + " réplicas y responden " + available);
	}
}
