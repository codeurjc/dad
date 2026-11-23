package es.codeurjc.dad.ddd.ejem3.shipping.domain;

/**
 * Puerto hacia el transportista, expresado en el lenguaje de Logística.
 * Logística no sabe (ni quiere saber) cómo es la API del transportista real.
 */
public interface CarrierGateway {

	TrackingNumber book(Shipment shipment);
}
