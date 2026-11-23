package es.codeurjc.dad.seg.ejem2;

import java.net.URI;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/productos")
public class ProductoController {

	private final Map<Long, Producto> productos = new ConcurrentHashMap<>();
	private final AtomicLong ids = new AtomicLong();

	public ProductoController() {
		crear(new Producto(null, "Teclado", 49.9));
		crear(new Producto(null, "Ratón", 19.9));
	}

	// Público: lo configura SecurityConfig
	@GetMapping
	public Collection<Producto> listar() {
		return productos.values();
	}

	// Solo administradores: seguridad a nivel de método
	@PostMapping
	@PreAuthorize("hasRole('admin')")
	public ResponseEntity<Producto> crearProducto(@RequestBody Producto producto) {
		Producto creado = crear(producto);
		return ResponseEntity.created(URI.create("/api/productos/" + creado.id())).body(creado);
	}

	@DeleteMapping("/{id}")
	@PreAuthorize("hasRole('admin')")
	public ResponseEntity<Void> borrar(@PathVariable long id) {
		return productos.remove(id) != null ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
	}

	private Producto crear(Producto p) {
		long id = ids.incrementAndGet();
		Producto nuevo = new Producto(id, p.nombre(), p.precio());
		productos.put(id, nuevo);
		return nuevo;
	}
}
