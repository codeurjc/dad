package es.codeurjc.dad.balanceo.ejem2;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Comprobacion minima: el contexto arranca y Redis responde.
 */
@SpringBootTest
@Testcontainers
class SmokeTest {

	@Container
	@ServiceConnection(name = "redis")
	static GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

	@Autowired
	private RedisConnectionFactory redisConnectionFactory;

	@Test
	void redisResponde() {
		assertEquals("PONG", redisConnectionFactory.getConnection().ping());
	}
}
