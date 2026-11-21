package es.codeurjc.dad.ddd.ejer1.infrastructure;

import java.time.Clock;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import es.codeurjc.dad.ddd.ejer1.domain.Copy;
import es.codeurjc.dad.ddd.ejer1.domain.CopyId;
import es.codeurjc.dad.ddd.ejer1.domain.CopyRepository;
import es.codeurjc.dad.ddd.ejer1.domain.Member;
import es.codeurjc.dad.ddd.ejer1.domain.MemberId;
import es.codeurjc.dad.ddd.ejer1.domain.MemberRepository;

@Configuration
public class LibraryConfig {

	/** Inyectar el reloj permite controlar "hoy" en los tests. */
	@Bean
	Clock clock() {
		return Clock.systemDefaultZone();
	}

	@Bean
	CommandLineRunner sampleData(MemberRepository members, CopyRepository copies) {
		return args -> {
			members.save(new Member(new MemberId("m-1"), "Ana"));
			members.save(new Member(new MemberId("m-2"), "Luis"));
			copies.save(new Copy(new CopyId("c-1"), "978-0321125217", "Domain-Driven Design"));
			copies.save(new Copy(new CopyId("c-2"), "978-0321834577", "Implementing Domain-Driven Design"));
			copies.save(new Copy(new CopyId("c-3"), "978-0134434421", "Domain-Driven Design Distilled"));
			copies.save(new Copy(new CopyId("c-4"), "978-1617294549", "Microservices Patterns"));
			copies.save(new Copy(new CopyId("c-5"), "978-1492034025", "Fundamentals of Software Architecture"));
		};
	}
}
