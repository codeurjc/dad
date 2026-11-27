package es.codeurjc.dad.ddd.ejem3.shipping.infrastructure;

import java.util.Map;

import org.springframework.stereotype.Component;

import es.codeurjc.dad.ddd.ejem3.shipping.domain.ProductWeights;

@Component
public class InMemoryProductWeights implements ProductWeights {

	private static final int DEFAULT_GRAMS = 500;

	private final Map<String, Integer> grams = Map.of(
			"BOOK-DDD", 1_200,
			"MUG-URJC", 350,
			"LAPTOP", 2_100,
			"FRIDGE", 65_000);

	@Override
	public int gramsOf(String productCode) {
		return grams.getOrDefault(productCode, DEFAULT_GRAMS);
	}
}
