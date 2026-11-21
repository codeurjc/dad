package es.codeurjc.dad.ddd.ejer1.domain;

import java.util.Optional;

public interface CopyRepository {

	Optional<Copy> findById(CopyId id);

	void save(Copy entity);
}
