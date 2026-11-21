package es.codeurjc.dad.eventos.ejem4.web;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import es.codeurjc.dad.eventos.ejem4.application.AccountCommandService;
import es.codeurjc.dad.eventos.ejem4.domain.AccountEvent;
import es.codeurjc.dad.eventos.ejem4.domain.AccountException;
import es.codeurjc.dad.eventos.ejem4.domain.BankAccount;
import es.codeurjc.dad.eventos.ejem4.eventstore.ConcurrencyException;
import es.codeurjc.dad.eventos.ejem4.eventstore.EventStore;
import es.codeurjc.dad.eventos.ejem4.query.AccountProjections;
import es.codeurjc.dad.eventos.ejem4.query.AccountSummary;
import es.codeurjc.dad.eventos.ejem4.query.Movement;

/**
 * Comandos (POST) y consultas (GET) están separados: los POST van al modelo
 * de escritura (event store) y los GET a las proyecciones.
 *
 * <pre>
 * POST /accounts                     {"owner":"Ana"}
 * POST /accounts/{id}/deposits       {"amount":100}
 * POST /accounts/{id}/withdrawals    {"amount":30}
 * POST /accounts/{id}/close
 * GET  /accounts/{id}                resumen (proyección)
 * GET  /accounts/{id}/statement      extracto (proyección)
 * GET  /accounts/richest?n=3         ranking (proyección)
 * GET  /accounts/{id}/events         los eventos tal cual (event store)
 * GET  /accounts/{id}/balance?atVersion=2   "viaje en el tiempo"
 * </pre>
 */
@RestController
public class AccountController {

	public record OpenRequest(String owner) {
	}

	public record AmountRequest(BigDecimal amount) {
	}

	public record OpenResponse(String accountId) {
	}

	public record BalanceAt(String accountId, int version, BigDecimal balance) {
	}

	public record EventView(int version, String type, AccountEvent data) {
	}

	private final AccountCommandService commands;
	private final AccountProjections projections;
	private final EventStore store;

	public AccountController(AccountCommandService commands, AccountProjections projections, EventStore store) {
		this.commands = commands;
		this.projections = projections;
		this.store = store;
	}

	// ---------- Comandos ----------

	@PostMapping("/accounts")
	@ResponseStatus(HttpStatus.CREATED)
	public OpenResponse open(@RequestBody OpenRequest request) {
		return new OpenResponse(commands.openAccount(request.owner()));
	}

	@PostMapping("/accounts/{id}/deposits")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public void deposit(@PathVariable String id, @RequestBody AmountRequest request) {
		commands.deposit(id, request.amount());
	}

	@PostMapping("/accounts/{id}/withdrawals")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public void withdraw(@PathVariable String id, @RequestBody AmountRequest request) {
		commands.withdraw(id, request.amount());
	}

	@PostMapping("/accounts/{id}/close")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public void close(@PathVariable String id) {
		commands.close(id);
	}

	// ---------- Consultas ----------

	@GetMapping("/accounts/richest")
	public List<AccountSummary> richest(@RequestParam(defaultValue = "3") int n) {
		return projections.richest(n);
	}

	@GetMapping("/accounts/{id}")
	public AccountSummary summary(@PathVariable String id) {
		return projections.summary(id).orElseThrow(() -> new AccountException("No existe la cuenta " + id));
	}

	@GetMapping("/accounts/{id}/statement")
	public List<Movement> statement(@PathVariable String id) {
		return projections.statement(id);
	}

	@GetMapping("/accounts/{id}/events")
	public List<EventView> events(@PathVariable String id) {
		List<AccountEvent> history = store.load(id);
		return java.util.stream.IntStream.range(0, history.size())
				.mapToObj(i -> new EventView(i + 1, history.get(i).getClass().getSimpleName(), history.get(i)))
				.toList();
	}

	@GetMapping("/accounts/{id}/balance")
	public BalanceAt balanceAt(@PathVariable String id, @RequestParam int atVersion) {
		List<AccountEvent> history = store.load(id);
		int n = Math.min(atVersion, history.size());
		return new BalanceAt(id, n, BankAccount.replay(history.subList(0, n)).balance());
	}

	@ExceptionHandler(AccountException.class)
	@ResponseStatus(HttpStatus.CONFLICT)
	public String rejected(AccountException e) {
		return e.getMessage();
	}

	@ExceptionHandler(ConcurrencyException.class)
	@ResponseStatus(HttpStatus.CONFLICT)
	public String conflict(ConcurrencyException e) {
		return e.getMessage();
	}
}
