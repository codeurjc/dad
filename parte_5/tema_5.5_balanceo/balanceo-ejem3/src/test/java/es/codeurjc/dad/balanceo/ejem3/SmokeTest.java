package es.codeurjc.dad.balanceo.ejem3;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

/**
 * Comprobacion minima: el servidor arranca con el certificado del keystore.
 * Con RANDOM_PORT se levanta Tomcat de verdad y se inicializa TLS; con el
 * entorno por defecto (MOCK) no se carga el keystore y el test pasaria aunque
 * el fichero, la contrasena o el alias estuvieran mal.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class SmokeTest {

	@Test
	void elContextoArranca() {
	}
}
