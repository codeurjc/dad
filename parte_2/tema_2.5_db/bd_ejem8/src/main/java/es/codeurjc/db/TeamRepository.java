package es.codeurjc.db;

import org.springframework.data.jpa.repository.JpaRepository;

import es.codeurjc.db.model.Team;

public interface TeamRepository extends JpaRepository<Team, Long> {
	
}