package es.codeurjc.dad.k8s.ejem2;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class NotaControllerTest {

	@Autowired
	private NotaController controller;

	@Test
	void guardaYListaNotas() {
		controller.crear(Map.of("texto", "Desplegar en Kubernetes"));
		assertEquals(1, controller.listar().size());
		assertEquals("Desplegar en Kubernetes", controller.listar().get(0).getTexto());
		assertEquals(1L, controller.info().get("notas"));
	}
}
