package es.codeurjc.dad.seg.ejem3.pedidos;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PedidoController {

	public record Pedido(String producto, int unidades) {
	}

	private final InventarioClient inventario;

	public PedidoController(InventarioClient inventario) {
		this.inventario = inventario;
	}

	@PostMapping("/api/pedidos")
	public ResponseEntity<String> crear(@RequestBody Pedido pedido) {
		int disponibles = inventario.unidades(pedido.producto());
		if (disponibles < pedido.unidades()) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Solo quedan " + disponibles + " unidades");
		}
		return ResponseEntity.status(HttpStatus.CREATED).body("Pedido aceptado");
	}
}
