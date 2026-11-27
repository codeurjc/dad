package es.codeurjc.dad.fund.ejem2;

import java.util.List;

/**
 * Ejecuta: mvn -q compile exec:java -Dexec.mainClass=es.codeurjc.dad.fund.ejem2.Demo
 */
public class Demo {

	public static void main(String[] args) {
		scenario(1, 1);
		scenario(2, 2);
	}

	static void scenario(int w, int r) {
		List<Replica> rs = List.of(new Replica("r1"), new Replica("r2"), new Replica("r3"));
		QuorumStore store = new QuorumStore(rs, w, r);
		System.out.printf("%nN=3, W=%d, R=%d (W+R %s N)%n", w, r, w + r > 3 ? ">" : "≤");
		store.put("saldo", "100");
		store.propagate();
		store.put("saldo", "40");
		for (int i = 0; i < 3; i++) {
			System.out.println("  lectura " + (i + 1) + ": " + store.get("saldo").orElse("-"));
		}
		rs.get(0).crash();
		rs.get(1).crash();
		try {
			store.get("saldo");
			System.out.println("  con 2 réplicas caídas: lectura OK (disponible)");
		} catch (QuorumException e) {
			System.out.println("  con 2 réplicas caídas: " + e.getMessage());
		}
	}
}
