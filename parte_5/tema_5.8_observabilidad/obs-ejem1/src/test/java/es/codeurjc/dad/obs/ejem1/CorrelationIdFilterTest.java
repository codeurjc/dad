package es.codeurjc.dad.obs.ejem1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class CorrelationIdFilterTest {

	private final CorrelationIdFilter filter = new CorrelationIdFilter();

	@Test
	void reutilizaElIdQueLlegaEnLaCabecera() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(CorrelationIdFilter.HEADER, "abc-123");
		MockHttpServletResponse response = new MockHttpServletResponse();
		AtomicReference<String> duringRequest = new AtomicReference<>();

		filter.doFilter(request, response, (req, res) -> duringRequest.set(MDC.get(CorrelationIdFilter.MDC_KEY)));

		assertEquals("abc-123", duringRequest.get(), "disponible en el MDC durante la petición");
		assertEquals("abc-123", response.getHeader(CorrelationIdFilter.HEADER));
		assertNull(MDC.get(CorrelationIdFilter.MDC_KEY), "y se limpia al terminar");
	}

	@Test
	void generaUnIdSiNoVieneOEsSospechoso() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(CorrelationIdFilter.HEADER, "<script>alert(1)</script>");
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, (req, res) -> {
		});

		String id = response.getHeader(CorrelationIdFilter.HEADER);
		assertNotNull(id);
		assertEquals(36, id.length());
	}
}
