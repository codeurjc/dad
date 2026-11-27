package es.codeurjc.dad.obs.ejem1;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Identificador de correlación: un valor único por petición que aparece en
 * TODAS las líneas de log que genera esa petición (y que se propaga a otros
 * servicios en la cabecera X-Correlation-Id).
 *
 * Se guarda en el MDC (Mapped Diagnostic Context) de SLF4J: un mapa ligado al
 * hilo que el sistema de logs añade automáticamente a cada línea.
 *
 * (Con trazas distribuidas, ejemplo 3, el traceId cumple esta función y Spring
 * lo añade al MDC sin escribir este filtro.)
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

	public static final String HEADER = "X-Correlation-Id";
	public static final String MDC_KEY = "correlationId";

	private static final Pattern VALID = Pattern.compile("[A-Za-z0-9-]{1,64}");

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String id = request.getHeader(HEADER);
		if (id == null || !VALID.matcher(id).matches()) {
			// Si no viene (o viene algo raro: ¡nunca confíes en una cabecera!) se genera
			id = UUID.randomUUID().toString();
		}
		MDC.put(MDC_KEY, id);
		response.setHeader(HEADER, id);
		try {
			chain.doFilter(request, response);
		} finally {
			// Los hilos se reutilizan: hay que limpiar el MDC al terminar
			MDC.remove(MDC_KEY);
		}
	}
}
