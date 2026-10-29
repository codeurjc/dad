package es.urjc.code.example;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Comprobacion minima: la aplicacion arranca y procesa los argumentos.
 */
class SmokeTest {

	@Test
	void laAplicacionArrancaYLeeLosArgumentos() throws Exception {
		PrintStream salidaOriginal = System.out;
		ByteArrayOutputStream capturada = new ByteArrayOutputStream();

		try {
			System.setOut(new PrintStream(capturada, true, StandardCharsets.UTF_8));
			Application.main(new String[] { "uno", "dos" });
		} finally {
			System.setOut(salidaOriginal);
		}

		String salida = capturada.toString(StandardCharsets.UTF_8);

		assertTrue(salida.contains("Command line application"));
		assertTrue(salida.contains("uno"));
		assertTrue(salida.contains("dos"));
	}
}
