package es.codeurjc.dad.micro.ejem1.pedidos;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Llama al catálogo por HTTP. Es una llamada por RED: puede tardar, fallar o
 * no llegar nunca (el ejemplo 3 trata cómo protegerse).
 */
@Component
public class RestCatalogClient implements CatalogClient {

	private final RestClient http;

	public RestCatalogClient(@Value("${catalogo.url}") String catalogUrl) {
		this.http = RestClient.builder().baseUrl(catalogUrl).build();
	}

	@Override
	public Optional<ProductInfo> findProduct(Long productId) {
		try {
			return Optional.ofNullable(http.get().uri("/products/{id}", productId).retrieve().body(ProductInfo.class));
		} catch (HttpClientErrorException.NotFound e) {
			return Optional.empty();
		}
	}
}
