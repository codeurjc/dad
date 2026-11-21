package es.codeurjc.dad.micro.ejem1.catalogo;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * API pública del catálogo. Es su CONTRATO con los demás servicios: puede
 * cambiar su base de datos por dentro, pero no esta API sin avisar.
 */
@RestController
@RequestMapping("/products")
public class ProductController {

	private final ProductRepository products;

	public ProductController(ProductRepository products) {
		this.products = products;
	}

	@GetMapping
	public List<Product> all() {
		return products.findAll();
	}

	@GetMapping("/{id}")
	public ResponseEntity<Product> one(@PathVariable Long id) {
		return products.findById(id).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
	}
}
