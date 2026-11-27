package es.codeurjc.dad.eventos.ejer1.pagos;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Saldo de los monederos de los clientes. Java puro, sin Spring.
 *
 * Guarda el resultado de cada cobro por pedido: si llega dos veces el mismo
 * mensaje, devolvemos el mismo resultado sin cobrar dos veces (idempotencia).
 */
public class Wallets {

	public record ChargeResult(boolean accepted, String reason) {
	}

	private final Map<String, BigDecimal> balances = new HashMap<>();
	private final Map<String, ChargeResult> chargesByOrder = new HashMap<>();

	public Wallets(Map<String, BigDecimal> initialBalances) {
		balances.putAll(initialBalances);
	}

	public synchronized ChargeResult charge(String orderId, String customerId, BigDecimal amount) {
		ChargeResult previous = chargesByOrder.get(orderId);
		if (previous != null) {
			return previous;
		}
		BigDecimal balance = balances.get(customerId);
		ChargeResult result;
		if (balance == null) {
			result = new ChargeResult(false, "cliente " + customerId + " sin monedero");
		} else if (balance.compareTo(amount) < 0) {
			result = new ChargeResult(false, "saldo insuficiente (" + balance + " < " + amount + ")");
		} else {
			balances.put(customerId, balance.subtract(amount));
			result = new ChargeResult(true, null);
		}
		chargesByOrder.put(orderId, result);
		return result;
	}

	public synchronized Optional<BigDecimal> balanceOf(String customerId) {
		return Optional.ofNullable(balances.get(customerId));
	}
}
