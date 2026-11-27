package es.codeurjc.dad.ddd.ejer1.infrastructure;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import es.codeurjc.dad.ddd.ejer1.application.LibraryService;
import es.codeurjc.dad.ddd.ejer1.domain.CopyId;
import es.codeurjc.dad.ddd.ejer1.domain.LibraryException;
import es.codeurjc.dad.ddd.ejer1.domain.Loan;
import es.codeurjc.dad.ddd.ejer1.domain.Member;
import es.codeurjc.dad.ddd.ejer1.domain.MemberId;
import es.codeurjc.dad.ddd.ejer1.domain.Money;

/**
 * <pre>
 * GET  /members/{memberId}
 * POST /members/{memberId}/loans                     {"copyId":"c-1"}
 * POST /members/{memberId}/returns                   {"copyId":"c-1"}
 * POST /members/{memberId}/loans/{copyId}/renewal
 * POST /members/{memberId}/penalty-payments          {"amount":1.50}
 * </pre>
 */
@RestController
public class LibraryController {

	public record CopyRequest(String copyId) {
	}

	public record PaymentRequest(BigDecimal amount) {
	}

	public record LoanView(String copyId, LocalDate startDate, LocalDate dueDate, boolean renewed) {

		static LoanView of(Loan l) {
			return new LoanView(l.copyId().value(), l.startDate(), l.dueDate(), l.renewed());
		}
	}

	public record MemberView(String id, String name, List<LoanView> activeLoans, BigDecimal pendingPenalty) {

		static MemberView of(Member m) {
			return new MemberView(m.id().value(), m.name(), m.activeLoans().stream().map(LoanView::of).toList(),
					m.pendingPenalty().amount());
		}
	}

	public record ReturnView(String copyId, BigDecimal penalty) {
	}

	private final LibraryService service;

	public LibraryController(LibraryService service) {
		this.service = service;
	}

	@GetMapping("/members/{memberId}")
	public MemberView member(@PathVariable String memberId) {
		return MemberView.of(service.findMember(new MemberId(memberId)));
	}

	@PostMapping("/members/{memberId}/loans")
	@ResponseStatus(HttpStatus.CREATED)
	public LoanView borrow(@PathVariable String memberId, @RequestBody CopyRequest request) {
		return LoanView.of(service.borrow(new MemberId(memberId), new CopyId(request.copyId())));
	}

	@PostMapping("/members/{memberId}/returns")
	public ReturnView giveBack(@PathVariable String memberId, @RequestBody CopyRequest request) {
		Money penalty = service.giveBack(new MemberId(memberId), new CopyId(request.copyId()));
		return new ReturnView(request.copyId(), penalty.amount());
	}

	@PostMapping("/members/{memberId}/loans/{copyId}/renewal")
	public MemberView renew(@PathVariable String memberId, @PathVariable String copyId) {
		service.renew(new MemberId(memberId), new CopyId(copyId));
		return member(memberId);
	}

	@PostMapping("/members/{memberId}/penalty-payments")
	public MemberView pay(@PathVariable String memberId, @RequestBody PaymentRequest request) {
		service.payPenalty(new MemberId(memberId), new Money(request.amount()));
		return member(memberId);
	}

	@ExceptionHandler(LibraryException.class)
	@ResponseStatus(HttpStatus.CONFLICT)
	public String ruleViolated(LibraryException e) {
		return e.getMessage();
	}
}
