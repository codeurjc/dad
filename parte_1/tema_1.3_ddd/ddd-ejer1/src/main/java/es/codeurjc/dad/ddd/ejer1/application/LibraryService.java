package es.codeurjc.dad.ddd.ejer1.application;

import java.time.Clock;
import java.time.LocalDate;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import es.codeurjc.dad.ddd.ejer1.domain.Copy;
import es.codeurjc.dad.ddd.ejer1.domain.CopyId;
import es.codeurjc.dad.ddd.ejer1.domain.CopyRepository;
import es.codeurjc.dad.ddd.ejer1.domain.LendingPolicy;
import es.codeurjc.dad.ddd.ejer1.domain.LibraryException;
import es.codeurjc.dad.ddd.ejer1.domain.Loan;
import es.codeurjc.dad.ddd.ejer1.domain.Member;
import es.codeurjc.dad.ddd.ejer1.domain.MemberId;
import es.codeurjc.dad.ddd.ejer1.domain.MemberRepository;
import es.codeurjc.dad.ddd.ejer1.domain.Money;

/**
 * Servicio de aplicación del contexto de Préstamos.
 *
 * Decisión de diseño: prestar y devolver modifican DOS agregados (Member y
 * Copy) en la misma operación. La regla general es "un agregado por
 * transacción"; aquí la incumplimos conscientemente porque ambos viven en el
 * mismo servicio y la consistencia inmediata es un requisito (no podemos
 * prestar dos veces el mismo ejemplar). La alternativa sería actualizar Copy
 * de forma asíncrona reaccionando al evento CopyBorrowed y aceptar
 * consistencia eventual (y compensar si el ejemplar ya estaba prestado).
 *
 * Los métodos son synchronized porque los repositorios son en memoria; con
 * una base de datos usaríamos @Transactional y bloqueo optimista.
 */
@Service
public class LibraryService {

	private final MemberRepository members;
	private final CopyRepository copies;
	private final ApplicationEventPublisher events;
	private final Clock clock;
	private final LendingPolicy lending = new LendingPolicy();

	public LibraryService(MemberRepository members, CopyRepository copies, ApplicationEventPublisher events,
			Clock clock) {
		this.members = members;
		this.copies = copies;
		this.events = events;
		this.clock = clock;
	}

	public synchronized Loan borrow(MemberId memberId, CopyId copyId) {
		Member member = member(memberId);
		Copy copy = copy(copyId);
		Loan loan = lending.lend(member, copy, today());
		save(member, copy);
		return loan;
	}

	public synchronized Money giveBack(MemberId memberId, CopyId copyId) {
		Member member = member(memberId);
		Copy copy = copy(copyId);
		Money penalty = lending.giveBack(member, copy, today());
		save(member, copy);
		return penalty;
	}

	public synchronized void renew(MemberId memberId, CopyId copyId) {
		Member member = member(memberId);
		member.renew(copyId, today());
		members.save(member);
		member.pullEvents().forEach(events::publishEvent);
	}

	public synchronized void payPenalty(MemberId memberId, Money amount) {
		Member member = member(memberId);
		member.payPenalty(amount);
		members.save(member);
	}

	public Member findMember(MemberId memberId) {
		return member(memberId);
	}

	public Copy findCopy(CopyId copyId) {
		return copy(copyId);
	}

	private void save(Member member, Copy copy) {
		members.save(member);
		copies.save(copy);
		member.pullEvents().forEach(events::publishEvent);
	}

	private LocalDate today() {
		return LocalDate.now(clock);
	}

	private Member member(MemberId id) {
		return members.findById(id).orElseThrow(() -> new LibraryException("No existe el socio " + id));
	}

	private Copy copy(CopyId id) {
		return copies.findById(id).orElseThrow(() -> new LibraryException("No existe el ejemplar " + id));
	}
}
