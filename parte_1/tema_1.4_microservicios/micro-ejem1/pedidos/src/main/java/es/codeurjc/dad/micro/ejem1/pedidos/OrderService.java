package es.codeurjc.dad.micro.ejem1.pedidos;

import org.springframework.stereotype.Service;

@Service
public class OrderService {

	private final OrderRepository orders;
	private final CatalogClient catalog;

	public OrderService(OrderRepository orders, CatalogClient catalog) {
		this.orders = orders;
		this.catalog = catalog;
	}

	public Order placeOrder(Long productId, int quantity) {
		if (quantity <= 0) {
			throw new IllegalArgumentException("La cantidad debe ser positiva");
		}
		ProductInfo product = catalog.findProduct(productId)
				.orElseThrow(() -> new IllegalArgumentException("No existe el producto " + productId));
		if (product.stock() < quantity) {
			throw new IllegalStateException("No hay stock suficiente de " + product.name());
		}
		return orders.save(new Order(product.id(), product.name(), product.price(), quantity));
	}
}
