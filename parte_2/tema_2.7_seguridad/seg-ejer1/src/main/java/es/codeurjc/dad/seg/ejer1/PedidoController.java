package es.codeurjc.dad.seg.ejer1;

import java.net.URI;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/pedidos")
public class PedidoController {

	private final PedidoService service;

	public PedidoController(PedidoService service) {
		this.service = service;
	}

	@GetMapping
	public List<Pedido> listar(Authentication usuario) {
		return service.listar(usuario);
	}

	@GetMapping("/{id}")
	public ResponseEntity<Pedido> ver(@PathVariable long id, Authentication usuario) {
		return ResponseEntity.of(service.buscar(id, usuario));
	}

	@PostMapping
	public ResponseEntity<Pedido> crear(@RequestBody NuevoPedido nuevo, Authentication usuario) {
		Pedido pedido = service.crear(nuevo, usuario);
		return ResponseEntity.created(URI.create("/api/pedidos/" + pedido.id())).body(pedido);
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<Pedido> cancelar(@PathVariable long id, Authentication usuario) {
		return ResponseEntity.of(service.cancelar(id, usuario));
	}

	@ExceptionHandler(PedidoService.PedidoNoCancelableException.class)
	public ResponseEntity<String> noCancelable(PedidoService.PedidoNoCancelableException e) {
		return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
	}
}
