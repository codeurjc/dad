package es.codeurjc.dad.seg.ejer1;

public record Pedido(long id, String propietario, String producto, int unidades, Estado estado) {

	public enum Estado {
		PENDIENTE, ENVIADO, CANCELADO
	}

	public Pedido conEstado(Estado nuevo) {
		return new Pedido(id, propietario, producto, unidades, nuevo);
	}
}
