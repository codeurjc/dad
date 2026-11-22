package es.codeurjc.dad.seg.ejer1;

/**
 * DTO de entrada: SOLO los campos que el cliente puede decidir.
 * Si se recibiera directamente un Pedido, un cliente podría enviar
 * "propietario" o "estado" (asignación masiva / mass assignment).
 */
public record NuevoPedido(String producto, int unidades) {
}
