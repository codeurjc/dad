package es.codeurjc.db;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Comprobacion minima: el contexto arranca y la base de datos responde.
 */
@SpringBootTest(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
@ActiveProfiles("prod")
@Testcontainers
class SmokeTest {

	@Container
	@ServiceConnection
	static MySQLContainer mysql = new MySQLContainer("mysql:8.0");

	@Autowired
	private DataSource dataSource;

	@Test
	void elContextoArranca() {
	}

	@Test
	void laBaseDeDatosResponde() throws Exception {
		try (Connection conexion = dataSource.getConnection()) {
			assertTrue(conexion.isValid(5));
		}
	}
}
