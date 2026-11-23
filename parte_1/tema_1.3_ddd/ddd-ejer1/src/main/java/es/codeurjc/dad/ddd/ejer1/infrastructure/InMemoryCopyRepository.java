package es.codeurjc.dad.ddd.ejer1.infrastructure;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Repository;

import es.codeurjc.dad.ddd.ejer1.domain.Copy;
import es.codeurjc.dad.ddd.ejer1.domain.CopyId;
import es.codeurjc.dad.ddd.ejer1.domain.CopyRepository;

@Repository
public class InMemoryCopyRepository implements CopyRepository {

	private final Map<CopyId, Copy> copies = new ConcurrentHashMap<>();

	@Override
	public Optional<Copy> findById(CopyId id) {
		return Optional.ofNullable(copies.get(id));
	}

	@Override
	public void save(Copy copy) {
		copies.put(copy.id(), copy);
	}
}
