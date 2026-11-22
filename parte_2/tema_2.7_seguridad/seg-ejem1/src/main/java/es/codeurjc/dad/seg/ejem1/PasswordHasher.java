package es.codeurjc.dad.seg.ejem1;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Hash de contraseñas con PBKDF2-HMAC-SHA256: sal aleatoria por usuario y muchas iteraciones
 * para que probar contraseñas por fuerza bruta sea LENTO.
 *
 * En Spring se usa un PasswordEncoder (BCryptPasswordEncoder, Argon2PasswordEncoder o
 * PasswordEncoderFactories.createDelegatingPasswordEncoder()). Esta clase muestra la idea.
 *
 * Formato almacenado: pbkdf2$iteraciones$sal$hash
 */
public class PasswordHasher {

	private static final SecureRandom RANDOM = new SecureRandom();
	private final int iterations;

	public PasswordHasher(int iterations) {
		this.iterations = iterations;
	}

	public String hash(char[] password) {
		byte[] salt = new byte[16];
		RANDOM.nextBytes(salt);
		byte[] hash = pbkdf2(password, salt, iterations);
		return "pbkdf2$" + iterations + "$" + b64(salt) + "$" + b64(hash);
	}

	public boolean matches(char[] password, String stored) {
		String[] p = stored.split("\\$");
		int storedIterations = Integer.parseInt(p[1]);
		byte[] salt = Base64.getDecoder().decode(p[2]);
		byte[] expected = Base64.getDecoder().decode(p[3]);
		return MessageDigest.isEqual(expected, pbkdf2(password, salt, storedIterations));
	}

	private static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
		try {
			PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
			return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private static String b64(byte[] b) {
		return Base64.getEncoder().encodeToString(b);
	}
}
