package es.codeurjc.dad.ddd.ejem3.shipping.domain;

import java.util.Objects;

/**
 * Agregado Envío del contexto de Logística.
 *
 * Fíjate en que no hay precios ni productos: hay un destinatario y un peso.
 * Es el pedido visto con los ojos de Logística.
 */
public class Shipment {

	/** Los envíos de más de 30 kg necesitan un servicio de carga. */
	public static final int MAX_STANDARD_WEIGHT_GRAMS = 30_000;

	private final ShipmentId id;
	private final String orderReference;
	private final Recipient recipient;
	private final int weightGrams;
	private ShipmentStatus status = ShipmentStatus.PENDING;
	private TrackingNumber trackingNumber;

	public Shipment(ShipmentId id, String orderReference, Recipient recipient, int weightGrams) {
		this.id = Objects.requireNonNull(id);
		this.orderReference = Objects.requireNonNull(orderReference);
		this.recipient = Objects.requireNonNull(recipient);
		if (weightGrams <= 0) {
			throw new IllegalArgumentException("Un envío debe pesar algo");
		}
		this.weightGrams = weightGrams;
	}

	public boolean requiresFreightService() {
		return weightGrams > MAX_STANDARD_WEIGHT_GRAMS;
	}

	public void booked(TrackingNumber trackingNumber) {
		if (status != ShipmentStatus.PENDING) {
			throw new IllegalStateException("El envío " + id + " ya estaba reservado");
		}
		this.trackingNumber = Objects.requireNonNull(trackingNumber);
		this.status = ShipmentStatus.BOOKED;
	}

	public ShipmentId id() {
		return id;
	}

	public String orderReference() {
		return orderReference;
	}

	public Recipient recipient() {
		return recipient;
	}

	public int weightGrams() {
		return weightGrams;
	}

	public ShipmentStatus status() {
		return status;
	}

	public TrackingNumber trackingNumber() {
		return trackingNumber;
	}
}
