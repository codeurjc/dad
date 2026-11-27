package es.codeurjc.dad.eventos.ejem4.application;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent;
import es.codeurjc.dad.eventos.ejem4.domain.AccountException;
import es.codeurjc.dad.eventos.ejem4.domain.BankAccount;
import es.codeurjc.dad.eventos.ejem4.eventstore.EventStore;

/**
 * Lado de ESCRITURA (comandos) de CQRS.
 *
 * Para cada comando: cargar los eventos → reconstruir el agregado → ejecutar el
 * comando → guardar los eventos nuevos con control de concurrencia optimista.
 */
public class AccountCommandService {

	private final EventStore store;

	public AccountCommandService(EventStore store) {
		this.store = store;
	}

	public String openAccount(String owner) {
		String id = "ES" + UUID.randomUUID().toString().replace("-", "").substring(0, 10).toUpperCase();
		BankAccount account = BankAccount.open(id, owner);
		store.append(id, 0, account.pullPendingEvents());
		return id;
	}

	public void deposit(String accountId, BigDecimal amount) {
		execute(accountId, account -> account.deposit(amount));
	}

	public void withdraw(String accountId, BigDecimal amount) {
		execute(accountId, account -> account.withdraw(amount));
	}

	public void close(String accountId) {
		execute(accountId, BankAccount::close);
	}

	private void execute(String accountId, Consumer<BankAccount> command) {
		List<AccountEvent> history = store.load(accountId);
		if (history.isEmpty()) {
			throw new AccountException("No existe la cuenta " + accountId);
		}
		BankAccount account = BankAccount.replay(history);
		int expectedVersion = account.version();
		command.accept(account);
		store.append(accountId, expectedVersion, account.pullPendingEvents());
	}
}
