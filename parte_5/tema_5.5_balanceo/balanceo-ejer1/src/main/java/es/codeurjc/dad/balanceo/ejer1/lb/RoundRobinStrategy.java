package es.codeurjc.dad.balanceo.ejer1.lb;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/** Por turnos: 1, 2, 3, 1, 2, 3... */
public class RoundRobinStrategy implements Strategy {

	private final AtomicLong counter = new AtomicLong();

	@Override
	public Backend choose(List<Backend> healthy, String clientKey) {
		int index = (int) (counter.getAndIncrement() % healthy.size());
		return healthy.get(index);
	}
}
