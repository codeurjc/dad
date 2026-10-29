package es.codeurjc.daw.library;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Comprobacion minima: el contexto arranca y la base de datos responde.
 */
@SpringBootTest
class SmokeTest {

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
