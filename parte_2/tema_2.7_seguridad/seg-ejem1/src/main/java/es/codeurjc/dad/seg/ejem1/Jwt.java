package es.codeurjc.dad.seg.ejem1;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * JWT firmado con HMAC-SHA256 (HS256) hecho a mano, SOLO para entender el formato.
 * En una aplicación real se usa una biblioteca (Nimbus, jjwt...) a través de Spring Security.
 *
 * Simplificación: los claims son un objeto JSON plano con valores String o enteros.
 */
public final class Jwt {

	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder B64D = Base64.getUrlDecoder();
	private static final String HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

	private Jwt() {
	}

	/** Genera header.payload.firma */
	public static String sign(Map<String, Object> claims, byte[] secret) {
		String header = b64(HEADER);
		String payload = b64(toJson(claims));
		return header + "." + payload + "." + hmac(header + "." + payload, secret);
	}

	/** Comprueba firma, algoritmo y caducidad. Devuelve los claims si todo es correcto. */
	public static Map<String, Object> verify(String token, byte[] secret, Clock clock) {
		String[] parts = token.split("\\.", -1);
		if (parts.length != 3) {
			throw new InvalidTokenException("formato incorrecto");
		}
		Map<String, Object> header = parseJson(new String(B64D.decode(parts[0]), StandardCharsets.UTF_8));
		// NUNCA aceptar el algoritmo que diga el token sin comprobarlo: "alg":"none" es un ataque clásico
		if (!"HS256".equals(header.get("alg"))) {
			throw new InvalidTokenException("algoritmo no permitido: " + header.get("alg"));
		}
		String expected = hmac(parts[0] + "." + parts[1], secret);
		// Comparación en tiempo constante para no filtrar información por tiempos de respuesta
		if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
				parts[2].getBytes(StandardCharsets.US_ASCII))) {
			throw new InvalidTokenException("firma incorrecta");
		}
		Map<String, Object> claims = parseJson(new String(B64D.decode(parts[1]), StandardCharsets.UTF_8));
		Object exp = claims.get("exp");
		if (!(exp instanceof Long e) || clock.instant().getEpochSecond() >= e) {
			throw new InvalidTokenException("token caducado o sin caducidad");
		}
		return claims;
	}

	/** Lo que puede hacer CUALQUIERA con el token: leer el payload (no está cifrado) */
	public static String decodePayload(String token) {
		return new String(B64D.decode(token.split("\\.")[1]), StandardCharsets.UTF_8);
	}

	private static String hmac(String data, byte[] secret) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(secret, "HmacSHA256"));
			return B64.encodeToString(mac.doFinal(data.getBytes(StandardCharsets.US_ASCII)));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private static String b64(String s) {
		return B64.encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}

	static String toJson(Map<String, Object> claims) {
		StringBuilder sb = new StringBuilder("{");
		claims.forEach((k, v) -> {
			if (sb.length() > 1) {
				sb.append(',');
			}
			sb.append('"').append(k).append("\":");
			sb.append(v instanceof Number ? v.toString() : "\"" + v.toString().replace("\"", "\\\"") + "\"");
		});
		return sb.append('}').toString();
	}

	private static final Pattern PAIR = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"((?:[^\"\\\\]|\\\\.)*)\"|-?\\d+)");

	static Map<String, Object> parseJson(String json) {
		Map<String, Object> map = new LinkedHashMap<>();
		Matcher m = PAIR.matcher(json);
		while (m.find()) {
			map.put(m.group(1), m.group(3) != null ? m.group(3).replace("\\\"", "\"") : Long.valueOf(m.group(2)));
		}
		return map;
	}
}
