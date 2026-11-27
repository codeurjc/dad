package es.codeurjc.dad.balanceo.ejer1.lb;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Hash consistente de la IP del cliente: el mismo cliente va siempre al mismo
 * servidor (afinidad sin cookies, como "balance source" en HAProxy).
 *
 * Cada servidor ocupa varios puntos ("nodos virtuales") en un anillo de
 * hashes. El cliente va al primer servidor que encuentra en el anillo a partir
 * de su hash. Si se añade o se quita un servidor, solo cambian de servidor los
 * clientes de su tramo del anillo (≈ 1/N), no todos (como pasaría con hash % N).
 */
public class ConsistentHashStrategy implements Strategy {

	private final int virtualNodes;

	public ConsistentHashStrategy(int virtualNodes) {
		this.virtualNodes = virtualNodes;
	}

	public ConsistentHashStrategy() {
		this(100);
	}

	@Override
	public Backend choose(List<Backend> healthy, String clientKey) {
		SortedMap<Long, Backend> ring = new TreeMap<>();
		for (Backend b : healthy) {
			for (int i = 0; i < virtualNodes; i++) {
				ring.put(hash(b.id() + "#" + i), b);
			}
		}
		SortedMap<Long, Backend> tail = ring.tailMap(hash(clientKey));
		Map.Entry<Long, Backend> entry = tail.isEmpty() ? ring.entrySet().iterator().next()
				: tail.entrySet().iterator().next();
		return entry.getValue();
	}

	static long hash(String key) {
		try {
			byte[] d = MessageDigest.getInstance("MD5").digest(key.getBytes(StandardCharsets.UTF_8));
			long h = 0;
			for (int i = 0; i < 8; i++) {
				h = (h << 8) | (d[i] & 0xff);
			}
			return h;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
