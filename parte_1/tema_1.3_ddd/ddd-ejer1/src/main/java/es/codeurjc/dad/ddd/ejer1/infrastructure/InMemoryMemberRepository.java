package es.codeurjc.dad.ddd.ejer1.infrastructure;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Repository;

import es.codeurjc.dad.ddd.ejer1.domain.Member;
import es.codeurjc.dad.ddd.ejer1.domain.MemberId;
import es.codeurjc.dad.ddd.ejer1.domain.MemberRepository;

@Repository
public class InMemoryMemberRepository implements MemberRepository {

	private final Map<MemberId, Member> members = new ConcurrentHashMap<>();

	@Override
	public Optional<Member> findById(MemberId id) {
		return Optional.ofNullable(members.get(id));
	}

	@Override
	public void save(Member member) {
		members.put(member.id(), member);
	}
}
