package es.codeurjc.dad.seg.ejem3.inventario;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StockController {

	public record Stock(String producto, int unidades) {
	}

	private final Map<String, Integer> stock = Map.of("teclado", 10, "raton", 0, "monitor", 3);

	@GetMapping("/api/stock/{producto}")
	public Stock stock(@PathVariable String producto, Authentication caller) {
		// caller.getName() es el cliente que llama (claim "azp"), no un usuario
		System.out.printf("Consulta de stock de %s por %s%n", producto, caller.getName());
		return new Stock(producto, stock.getOrDefault(producto, 0));
	}
}
