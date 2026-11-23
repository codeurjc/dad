package es.codeurjc.dad.seg.ejem1;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

public class Demo {

	public static void main(String[] args) {
		byte[] secret = "un-secreto-de-al-menos-32-bytes-!!".getBytes(StandardCharsets.UTF_8);
		long now = Instant.now().getEpochSecond();

		Map<String, Object> claims = new LinkedHashMap<>();
		claims.put("sub", "ana");
		claims.put("roles", "user");
		claims.put("iat", now);
		claims.put("exp", now + 300);

		String token = Jwt.sign(claims, secret);
		System.out.println("Token:\n  " + token.replace(".", "\n  ."));
		System.out.println("\nPayload (lo puede leer cualquiera, NO está cifrado):\n  " + Jwt.decodePayload(token));
		System.out.println("\nVerificado: " + Jwt.verify(token, secret, Clock.systemUTC()));

		// Un atacante se pone el rol de admin cambiando el payload...
		String[] parts = token.split("\\.");
		String fakePayload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
				Jwt.decodePayload(token).replace("\"user\"", "\"admin\"").getBytes(StandardCharsets.UTF_8));
		String forged = parts[0] + "." + fakePayload + "." + parts[2];
		try {
			Jwt.verify(forged, secret, Clock.systemUTC());
		} catch (InvalidTokenException e) {
			System.out.println("Token manipulado: " + e.getMessage());
		}

		PasswordHasher hasher = new PasswordHasher(600_000);
		long t0 = System.nanoTime();
		String stored = hasher.hash("patata123".toCharArray());
		System.out.printf("%nContraseña almacenada (%d ms): %s%n", (System.nanoTime() - t0) / 1_000_000, stored);
		System.out.println("Misma contraseña, otro hash (otra sal): " + hasher.hash("patata123".toCharArray()));
		System.out.println("¿patata123? " + hasher.matches("patata123".toCharArray(), stored));
		System.out.println("¿patata124? " + hasher.matches("patata124".toCharArray(), stored));
	}
}
