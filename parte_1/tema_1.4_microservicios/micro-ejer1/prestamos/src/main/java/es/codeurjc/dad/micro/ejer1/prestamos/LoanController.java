package es.codeurjc.dad.micro.ejer1.prestamos;

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

import es.codeurjc.dad.micro.ejer1.prestamos.LibrosClient.BookNotFoundException;
import es.codeurjc.dad.micro.ejer1.prestamos.LibrosClient.LibrosUnavailableException;
import es.codeurjc.dad.micro.ejer1.prestamos.LibrosClient.NoCopiesAvailableException;

/**
 * <pre>
 * POST /loans                 {"isbn":"978-0321125217","memberId":"ana"}
 * POST /loans/{id}/return
 * GET  /loans?memberId=ana
 * </pre>
 */
@RestController
public class LoanController {

	public record BorrowRequest(String isbn, String memberId) {
	}

	private final LoanService service;

	public LoanController(LoanService service) {
		this.service = service;
	}

	@PostMapping("/loans")
	@ResponseStatus(HttpStatus.CREATED)
	public Loan borrow(@RequestBody BorrowRequest request) {
		return service.borrow(request.isbn(), request.memberId());
	}

	@PostMapping("/loans/{id}/return")
	public Loan giveBack(@PathVariable Long id) {
		return service.giveBack(id);
	}

	@GetMapping("/loans")
	public List<Loan> loans(@RequestParam String memberId) {
		return service.loansOf(memberId);
	}

	@ExceptionHandler({ BookNotFoundException.class, IllegalArgumentException.class })
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public String notFound(RuntimeException e) {
		return e.getMessage();
	}

	@ExceptionHandler({ NoCopiesAvailableException.class, IllegalStateException.class })
	@ResponseStatus(HttpStatus.CONFLICT)
	public String conflict(RuntimeException e) {
		return e.getMessage();
	}

	@ExceptionHandler(LibrosUnavailableException.class)
	@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
	public String unavailable(LibrosUnavailableException e) {
		return e.getMessage();
	}
}
