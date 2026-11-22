package es.codeurjc.dad.fund.ejer1;

import java.util.List;

/**
 * Ejecuta: mvn -q compile exec:java -Dexec.mainClass=es.codeurjc.dad.fund.ejer1.Demo
 */
public class Demo {

	public static void main(String[] args) {
		Participant ana = new Participant(0, "Ana", 3);
		Participant luis = new Participant(1, "Luis", 3);
		Participant eva = new Participant(2, "Eva", 3);
		UnreliableNetwork net = new UnreliableNetwork(List.of(ana, luis, eva), 7);

		net.broadcast(ana.write("¿Quedamos a las 5?"));
		while (luis.conversation().isEmpty()) {
			net.deliver(0.5); // la pregunta va llegando...
		}
		net.broadcast(luis.write("¡Vale!")); // Luis responde tras leer la pregunta
		net.broadcast(eva.write("Hoy no puedo")); // Eva escribe a la vez (concurrente)
		net.deliver(1);

		for (Participant p : List.of(ana, luis, eva)) {
			System.out.println(p.name() + " ve:");
			p.conversation().forEach(line -> System.out.println("   " + line));
		}
	}
}
