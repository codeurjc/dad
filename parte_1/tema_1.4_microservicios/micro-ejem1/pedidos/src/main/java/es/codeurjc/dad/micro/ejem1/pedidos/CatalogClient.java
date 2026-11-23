package es.codeurjc.dad.micro.ejem1.pedidos;

import java.util.Optional;

/**
 * Puerto hacia el servicio de catálogo.
 */
public interface CatalogClient {

	Optional<ProductInfo> findProduct(Long productId);
}
