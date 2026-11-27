package es.codeurjc.dad.fund.ejem1;

/**
 * El escenario de las transparencias: tres procesos (A, B, C) y dos mensajes.
 *
 * <pre>
 * A:  a1 ──m1──────────────▶ (b2 en B)
 * B:        b1     b2 (recibe m1)   b3 ──m2──▶ (c2 en C)
 * C:  c1                                          c2 (recibe m2)
 * </pre>
 *
 * Ejecuta: mvn -q compile exec:java -Dexec.mainClass=es.codeurjc.dad.fund.ejem1.Demo
 */
public class Demo {

	public static void main(String[] args) {
		int a = 0, b = 1, c = 2;
		VectorClock va = VectorClock.zero(3), vb = VectorClock.zero(3), vc = VectorClock.zero(3);
		LamportClock la = new LamportClock(), lb = new LamportClock(), lc = new LamportClock();

		va = va.tick(a);                 long a1 = la.send();   VectorClock m1 = va;   // a1: envía m1
		vb = vb.tick(b);                 long b1 = lb.tick();   VectorClock vb1 = vb;  // b1: evento local
		vc = vc.tick(c);                 long c1 = lc.tick();   VectorClock vc1 = vc;  // c1: evento local
		vb = vb.merge(b, m1);            long b2 = lb.receive(a1); VectorClock vb2 = vb; // b2: recibe m1
		vb = vb.tick(b);                 long b3 = lb.send();   VectorClock m2 = vb;   // b3: envía m2
		vc = vc.merge(c, m2);            long c2 = lc.receive(b3); VectorClock vc2 = vc; // c2: recibe m2

		System.out.printf("a1  L=%d  V=%s%n", a1, m1);
		System.out.printf("b1  L=%d  V=%s%n", b1, vb1);
		System.out.printf("c1  L=%d  V=%s%n", c1, vc1);
		System.out.printf("b2  L=%d  V=%s%n", b2, vb2);
		System.out.printf("b3  L=%d  V=%s%n", b3, m2);
		System.out.printf("c2  L=%d  V=%s%n", c2, vc2);
		System.out.println();
		System.out.println("a1 vs c2: " + m1.compareTo(vc2) + "  -> a1 ocurre antes que c2 (a través de m1 y m2)");
		System.out.println("c1 vs b3: " + vc1.compareTo(m2) + "  -> aunque Lamport dé " + c1 + " < " + b3
				+ ": Lamport ordena, pero no detecta la concurrencia");
	}
}
