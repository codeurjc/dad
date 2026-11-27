package es.codeurjc.dad.seg.ejem1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class JwtTest {

	private static final byte[] SECRET = "un-secreto-de-al-menos-32-bytes-!!".getBytes(StandardCharsets.UTF_8);
	private static final Instant NOW = Instant.parse("2026-11-22T10:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

	private static Map<String, Object> claims(long expSeconds) {
		Map<String, Object> c = new LinkedHashMap<>();
		c.put("sub", "ana");
		c.put("roles", "user");
		c.put("exp", NOW.getEpochSecond() + expSeconds);
		return c;
	}

	private static String b64(String s) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}

	@Test
	void unTokenValidoSeVerifica() {
		String token = Jwt.sign(claims(60), SECRET);
		Map<String, Object> verified = Jwt.verify(token, SECRET, CLOCK);
		assertEquals("ana", verified.get("sub"));
		assertEquals("user", verified.get("roles"));
	}

	@Test
	void cambiarElPayloadInvalidaLaFirma() {
		String[] p = Jwt.sign(claims(60), SECRET).split("\\.");
		String forged = p[0] + "." + b64(Jwt.decodePayload(String.join(".", p)).replace("user", "admin")) + "." + p[2];
		assertThrows(InvalidTokenException.class, () -> Jwt.verify(forged, SECRET, CLOCK));
	}

	@Test
	void otroSecretoNoSirve() {
		String token = Jwt.sign(claims(60), "otro-secreto-distinto-de-32-bytes!!".getBytes(StandardCharsets.UTF_8));
		assertThrows(InvalidTokenException.class, () -> Jwt.verify(token, SECRET, CLOCK));
	}

	@Test
	void unTokenCaducadoSeRechaza() {
		String token = Jwt.sign(claims(-1), SECRET);
		assertThrows(InvalidTokenException.class, () -> Jwt.verify(token, SECRET, CLOCK));
	}

	@Test
	void algNoneSeRechaza() {
		String payload = b64("{\"sub\":\"ana\",\"roles\":\"admin\",\"exp\":" + (NOW.getEpochSecond() + 60) + "}");
		String token = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + payload + ".";
		InvalidTokenException e = assertThrows(InvalidTokenException.class, () -> Jwt.verify(token, SECRET, CLOCK));
		assertTrue(e.getMessage().contains("none"));
	}

	@Test
	void elPayloadNoEstaCifrado() {
		String token = Jwt.sign(claims(60), SECRET);
		assertTrue(Jwt.decodePayload(token).contains("\"sub\":\"ana\""));
	}

	@Test
	void hashDeContrasenas() {
		PasswordHasher hasher = new PasswordHasher(10_000);
		String h1 = hasher.hash("patata123".toCharArray());
		String h2 = hasher.hash("patata123".toCharArray());
		assertNotEquals(h1, h2, "la sal hace que el mismo password dé hashes distintos");
		assertTrue(hasher.matches("patata123".toCharArray(), h1));
		assertTrue(hasher.matches("patata123".toCharArray(), h2));
		assertFalse(hasher.matches("patata124".toCharArray(), h1));
	}
}
