package es.codeurjc.dad.ddd.ejem3.shipping.domain;

/**
 * Logística mantiene sus propios datos de producto: el peso. A Ventas el
 * peso no le importa, por eso no viaja en el evento de Ventas.
 */
public interface ProductWeights {

	int gramsOf(String productCode);
}
