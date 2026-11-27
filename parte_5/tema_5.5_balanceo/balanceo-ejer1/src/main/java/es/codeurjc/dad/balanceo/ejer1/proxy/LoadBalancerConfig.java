package es.codeurjc.dad.balanceo.ejer1.proxy;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import es.codeurjc.dad.balanceo.ejer1.lb.Backend;
import es.codeurjc.dad.balanceo.ejer1.lb.ConsistentHashStrategy;
import es.codeurjc.dad.balanceo.ejer1.lb.LeastConnectionsStrategy;
import es.codeurjc.dad.balanceo.ejer1.lb.LoadBalancer;
import es.codeurjc.dad.balanceo.ejer1.lb.RoundRobinStrategy;
import es.codeurjc.dad.balanceo.ejer1.lb.Strategy;
import es.codeurjc.dad.balanceo.ejer1.lb.WeightedRoundRobinStrategy;

@Configuration
public class LoadBalancerConfig {

	@Bean
	public LoadBalancer loadBalancer(@Value("${lb.backends}") List<String> urls,
			@Value("${lb.weights:}") List<Integer> weights, @Value("${lb.strategy}") String strategy,
			@Value("${lb.sticky}") boolean sticky) {
		List<Backend> backends = new ArrayList<>();
		for (int i = 0; i < urls.size(); i++) {
			int weight = i < weights.size() ? weights.get(i) : 1;
			backends.add(new Backend("s" + (i + 1), URI.create(urls.get(i).trim()), weight));
		}
		return new LoadBalancer(backends, strategy(strategy), sticky);
	}

	static Strategy strategy(String name) {
		return switch (name) {
			case "round-robin" -> new RoundRobinStrategy();
			case "weighted" -> new WeightedRoundRobinStrategy();
			case "least-connections" -> new LeastConnectionsStrategy();
			case "consistent-hash" -> new ConsistentHashStrategy();
			default -> throw new IllegalArgumentException("Estrategia desconocida: " + name);
		};
	}
}
