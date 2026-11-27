package es.codeurjc.dad.balanceo.ejem1;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

class InstanceControllerTest {

	@Test
	void elContadorCreceDentroDeLaMismaSesion() {
		InstanceController controller = new InstanceController("web-1");
		MockHttpSession session = new MockHttpSession();

		controller.visit(session);
		controller.visit(session);

		assertEquals(3, controller.visit(session).visits());
	}

	@Test
	void otraInstanciaNoConoceLaSesionDeLaPrimera() {
		InstanceController web1 = new InstanceController("web-1");
		InstanceController web2 = new InstanceController("web-2");

		web1.visit(new MockHttpSession());
		// web-2 no tiene la sesion de web-1 en su memoria: empieza de cero
		assertEquals(1, web2.visit(new MockHttpSession()).visits());
	}
}
