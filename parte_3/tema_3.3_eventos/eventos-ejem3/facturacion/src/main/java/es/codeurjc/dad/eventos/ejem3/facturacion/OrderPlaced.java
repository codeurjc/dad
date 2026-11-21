package es.codeurjc.dad.eventos.ejem3.facturacion;

import java.math.BigDecimal;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record OrderPlaced(String orderId, String customer, BigDecimal amount) {
}
