package es.codeurjc.dad.micro.ejem2.gateway;

import java.io.IOException;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Responsabilidad transversal en el gateway: cada petición sale con un
 * identificador (X-Request-Id) y se registra cuánto tarda. Los servicios no
 * tienen que implementarlo cada uno por su cuenta.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {

	private static final Logger log = LoggerFactory.getLogger(RequestIdFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String requestId = request.getHeader("X-Request-Id");
		if (requestId == null) {
			requestId = UUID.randomUUID().toString();
		}
		response.setHeader("X-Request-Id", requestId);
		long start = System.nanoTime();
		try {
			chain.doFilter(request, response);
		} finally {
			log.info("{} {} -> {} ({} ms) id={}", request.getMethod(), request.getRequestURI(), response.getStatus(),
					(System.nanoTime() - start) / 1_000_000, requestId);
		}
	}
}
