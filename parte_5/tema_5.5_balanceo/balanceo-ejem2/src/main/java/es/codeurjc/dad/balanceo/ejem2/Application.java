package es.codeurjc.dad.balanceo.ejem2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

/**
 * Las instancias no guardan estado de sesión en memoria: lo guardan en Redis.
 * Las instancias pasan a ser intercambiables (stateless), que es lo que
 * necesitamos para escalar horizontalmente y para la elasticidad.
 */
@SpringBootApplication
@EnableRedisHttpSession
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
}
