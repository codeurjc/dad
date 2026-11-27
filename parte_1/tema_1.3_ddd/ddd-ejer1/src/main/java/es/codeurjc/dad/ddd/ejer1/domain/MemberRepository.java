package es.codeurjc.dad.ddd.ejer1.domain;

import java.util.Optional;

public interface MemberRepository {

	Optional<Member> findById(MemberId id);

	void save(Member entity);
}
