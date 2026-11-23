package es.codeurjc.dad.fund.ejem1;

/**
 * Reloj lógico de Lamport (1978).
 *
 * Reglas:
 * <ol>
 * <li>Antes de cada evento local, incrementar el contador.</li>
 * <li>Al enviar un mensaje, incrementar y adjuntar el valor.</li>
 * <li>Al recibir un mensaje con marca t: contador = max(contador, t) + 1.</li>
 * </ol>
 *
 * Garantía: si a → b (a "ocurre antes" que b), entonces L(a) &lt; L(b).
 * Pero NO al revés: L(a) &lt; L(b) no implica que a ocurriera antes que b;
 * pueden ser concurrentes. Para detectar concurrencia hace falta un reloj
 * vectorial.
 */
public class LamportClock {

	private long time;

	public synchronized long tick() {
		return ++time;
	}

	public synchronized long send() {
		return ++time;
	}

	public synchronized long receive(long remoteTime) {
		time = Math.max(time, remoteTime) + 1;
		return time;
	}

	public synchronized long time() {
		return time;
	}
}
