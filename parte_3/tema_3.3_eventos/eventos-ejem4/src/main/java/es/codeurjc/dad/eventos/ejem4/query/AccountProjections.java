package es.codeurjc.dad.eventos.ejem4.query;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.AccountClosed;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.AccountOpened;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.MoneyDeposited;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent.MoneyWithdrawn;

/**
 * Lado de LECTURA (consultas) de CQRS: proyecciones.
 *
 * Escuchan los eventos y mantienen modelos desnormalizados, preparados para
 * responder rápido a cada consulta. Se pueden borrar y RECONSTRUIR en
 * cualquier momento volviendo a procesar todos los eventos, o crear nuevas
 * proyecciones a partir de la historia completa.
 *
 * Aquí se actualizan de forma síncrona; en un sistema distribuido lo harían
 * consumiendo los eventos de un broker y serían eventualmente consistentes.
 */
public class AccountProjections {

	private final Map<String, AccountSummary> summaries = new ConcurrentHashMap<>();
	private final Map<String, List<Movement>> statements = new ConcurrentHashMap<>();

	public void on(AccountEvent event) {
		switch (event) {
			case AccountOpened e -> {
				summaries.put(e.accountId(),
						new AccountSummary(e.accountId(), e.owner(), BigDecimal.ZERO, 0, e.occurredAt(), true));
				statements.put(e.accountId(), new ArrayList<>());
			}
			case MoneyDeposited e -> movement(e.accountId(), e.occurredAt(), "Ingreso", e.amount());
			case MoneyWithdrawn e -> movement(e.accountId(), e.occurredAt(), "Retirada", e.amount().negate());
			case AccountClosed e -> summaries.computeIfPresent(e.accountId(),
					(id, s) -> new AccountSummary(id, s.owner(), s.balance(), s.movements(), e.occurredAt(), false));
		}
	}

	private void movement(String accountId, java.time.Instant at, String concept, BigDecimal signedAmount) {
		AccountSummary s = summaries.get(accountId);
		BigDecimal newBalance = s.balance().add(signedAmount);
		summaries.put(accountId,
				new AccountSummary(accountId, s.owner(), newBalance, s.movements() + 1, at, s.open()));
		statements.get(accountId).add(new Movement(at, concept, signedAmount, newBalance));
	}

	public Optional<AccountSummary> summary(String accountId) {
		return Optional.ofNullable(summaries.get(accountId));
	}

	public List<Movement> statement(String accountId) {
		return List.copyOf(statements.getOrDefault(accountId, List.of()));
	}

	/** Una consulta que con el modelo de escritura sería costosa: las cuentas con más saldo. */
	public List<AccountSummary> richest(int n) {
		Collection<AccountSummary> all = summaries.values();
		return all.stream().sorted(Comparator.comparing(AccountSummary::balance).reversed()).limit(n).toList();
	}
}
