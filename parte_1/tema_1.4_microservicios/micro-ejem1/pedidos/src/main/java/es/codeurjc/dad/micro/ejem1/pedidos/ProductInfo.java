package es.codeurjc.dad.micro.ejem1.pedidos;

import java.math.BigDecimal;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Lo que Pedidos necesita saber de un producto. Es SU vista del producto, no
 * la entidad del catálogo (no compartimos clases entre servicios).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProductInfo(Long id, String name, BigDecimal price, int stock) {
}
