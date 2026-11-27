package es.codeurjc.dad.k8s.ejem3;

/** Trabajo intensivo en CPU para que el autoescalado tenga algo que medir */
public final class Primos {

	private Primos() {
	}

	public static int contarHasta(int n) {
		int total = 0;
		for (int i = 2; i <= n; i++) {
			if (esPrimo(i)) {
				total++;
			}
		}
		return total;
	}

	static boolean esPrimo(int n) {
		if (n < 2) {
			return false;
		}
		for (int d = 2; (long) d * d <= n; d++) {
			if (n % d == 0) {
				return false;
			}
		}
		return true;
	}
}
