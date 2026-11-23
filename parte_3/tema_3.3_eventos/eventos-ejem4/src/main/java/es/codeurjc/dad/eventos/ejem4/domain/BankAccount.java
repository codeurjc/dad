package es.codeurjc.dad.eventos.ejem4.domain;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.AccountClosed;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.AccountOpened;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.MoneyDeposited;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.MoneyWithdrawn;

/**
 * Agregado con event sourcing.
 *
 * <ul>
 * <li>Su estado se reconstruye aplicando, en orden, todos sus eventos pasados
 * ({@link #replay(List)}).</li>
 * <li>Los comandos (open, deposit, withdraw...) comprueban las reglas con el
 * estado actual y, si todo va bien, generan eventos nuevos. Nunca modifican el
 * estado directamente: lo hacen aplicando el evento ({@link #apply}).</li>
 * </ul>
 */
public class BankAccount {

	private final Clock clock;

	private String id;
	private String owner;
	private BigDecimal balance = BigDecimal.ZERO;
	private boolean open;
	private int version; // número de eventos aplicados

	private final List<AccountEvent> pendingEvents = new ArrayList<>();

	private BankAccount(Clock clock) {
		this.clock = clock;
	}

	/** Reconstruye la cuenta a partir de su historia. */
	public static BankAccount replay(List<AccountEvent> history) {
		return replay(history, Clock.systemUTC());
	}

	public static BankAccount replay(List<AccountEvent> history, Clock clock) {
		BankAccount account = new BankAccount(clock);
		history.forEach(account::apply);
		return account;
	}

	public static BankAccount open(String id, String owner) {
		return open(id, owner, Clock.systemUTC());
	}

	public static BankAccount open(String id, String owner, Clock clock) {
		if (owner == null || owner.isBlank()) {
			throw new AccountException("El titular es obligatorio");
		}
		BankAccount account = new BankAccount(clock);
		account.record(new AccountOpened(id, owner, account.now()));
		return account;
	}

	// ---------- Comandos ----------

	public void deposit(BigDecimal amount) {
		requireOpen();
		requirePositive(amount);
		record(new MoneyDeposited(id, amount, now()));
	}

	public void withdraw(BigDecimal amount) {
		requireOpen();
		requirePositive(amount);
		if (balance.compareTo(amount) < 0) {
			throw new AccountException("Saldo insuficiente: " + balance + " < " + amount);
		}
		record(new MoneyWithdrawn(id, amount, now()));
	}

	public void close() {
		requireOpen();
		if (balance.signum() != 0) {
			throw new AccountException("Solo se puede cerrar una cuenta con saldo 0 (saldo: " + balance + ")");
		}
		record(new AccountClosed(id, now()));
	}

	// ---------- Aplicación de eventos: aquí NO hay reglas, solo cambios de estado ----------

	private void apply(AccountEvent event) {
		switch (event) {
			case AccountOpened e -> {
				id = e.accountId();
				owner = e.owner();
				open = true;
			}
			case MoneyDeposited e -> balance = balance.add(e.amount());
			case MoneyWithdrawn e -> balance = balance.subtract(e.amount());
			case AccountClosed e -> open = false;
		}
		version++;
	}

	private void record(AccountEvent event) {
		apply(event);
		pendingEvents.add(event);
	}

	public List<AccountEvent> pullPendingEvents() {
		List<AccountEvent> events = List.copyOf(pendingEvents);
		pendingEvents.clear();
		return events;
	}

	/** Versión que tenía la cuenta antes de los eventos pendientes (para el control de concurrencia). */
	public int persistedVersion() {
		return version - pendingEvents.size();
	}

	private void requireOpen() {
		if (!open) {
			throw new AccountException("La cuenta " + id + " no está abierta");
		}
	}

	private static void requirePositive(BigDecimal amount) {
		if (amount == null || amount.signum() <= 0) {
			throw new AccountException("El importe debe ser positivo");
		}
	}

	private Instant now() {
		return Instant.now(clock);
	}

	public String id() {
		return id;
	}

	public String owner() {
		return owner;
	}

	public BigDecimal balance() {
		return balance;
	}

	public boolean isOpen() {
		return open;
	}

	public int version() {
		return version;
	}
}
