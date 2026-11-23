package es.codeurjc.dad.seg.ejem3.pedidos;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class InventarioClient {

	public record Stock(String producto, int unidades) {
	}

	private final RestClient inventario;

	public InventarioClient(RestClient inventarioRestClient) {
		this.inventario = inventarioRestClient;
	}

	public int unidades(String producto) {
		// No hay ni una línea de seguridad aquí: el interceptor añade el token
		return inventario.get().uri("/api/stock/{producto}", producto).retrieve().body(Stock.class).unidades();
	}
}
