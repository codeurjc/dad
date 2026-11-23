package es.codeurjc.dad.seg.ejer1;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import es.codeurjc.dad.seg.ejer1.Pedido.Estado;

@Service
public class PedidoService {

	public static class PedidoNoCancelableException extends RuntimeException {
		public PedidoNoCancelableException(Estado estado) {
			super("No se puede cancelar un pedido " + estado);
		}
	}

	private final Map<Long, Pedido> pedidos = new ConcurrentHashMap<>();
	private final AtomicLong ids = new AtomicLong();

	public PedidoService() {
		guardar("ana", new NuevoPedido("teclado", 1));
		guardar("luis", new NuevoPedido("monitor", 2));
	}

	/** La regla de autorización, en UN solo sitio */
	static boolean puedeVer(Pedido pedido, Authentication usuario) {
		return pedido.propietario().equals(usuario.getName()) || esSoporte(usuario);
	}

	private static boolean esSoporte(Authentication usuario) {
		return usuario.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_soporte"));
	}

	public List<Pedido> listar(Authentication usuario) {
		// Filtrar en la consulta, no traerlo todo y confiar en que el frontend oculte lo ajeno
		return pedidos.values().stream().filter(p -> puedeVer(p, usuario)).toList();
	}

	/** Vacío tanto si no existe como si no es suyo: así no se revela qué ids existen */
	public Optional<Pedido> buscar(long id, Authentication usuario) {
		return Optional.ofNullable(pedidos.get(id)).filter(p -> puedeVer(p, usuario));
	}

	public Pedido crear(NuevoPedido nuevo, Authentication usuario) {
		// El propietario sale del TOKEN, nunca del cuerpo de la petición
		return guardar(usuario.getName(), nuevo);
	}

	public Optional<Pedido> cancelar(long id, Authentication usuario) {
		return buscar(id, usuario).map(p -> {
			if (p.estado() != Estado.PENDIENTE) {
				throw new PedidoNoCancelableException(p.estado());
			}
			Pedido cancelado = p.conEstado(Estado.CANCELADO);
			pedidos.put(id, cancelado);
			return cancelado;
		});
	}

	private Pedido guardar(String propietario, NuevoPedido nuevo) {
		long id = ids.incrementAndGet();
		Pedido pedido = new Pedido(id, propietario, nuevo.producto(), nuevo.unidades(), Estado.PENDIENTE);
		pedidos.put(id, pedido);
		return pedido;
	}

	/** Para la demo: el almacén marca un pedido como enviado */
	void enviar(long id) {
		pedidos.computeIfPresent(id, (k, p) -> p.conEstado(Estado.ENVIADO));
	}
}
