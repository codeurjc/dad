package es.codeurjc.dad.micro.ejer1.prestamos;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface LoanRepository extends JpaRepository<Loan, Long> {

	List<Loan> findByMemberId(String memberId);

	long countByMemberIdAndReturnDateIsNull(String memberId);
}
