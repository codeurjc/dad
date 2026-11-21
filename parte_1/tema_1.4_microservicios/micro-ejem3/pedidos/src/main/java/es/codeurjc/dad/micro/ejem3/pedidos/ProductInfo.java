package es.codeurjc.dad.micro.ejem3.pedidos;

import java.math.BigDecimal;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ProductInfo(Long id, String name, BigDecimal price) {
}
