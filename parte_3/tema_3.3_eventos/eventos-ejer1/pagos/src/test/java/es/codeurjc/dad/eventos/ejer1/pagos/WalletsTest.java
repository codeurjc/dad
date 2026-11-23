package es.codeurjc.dad.eventos.ejer1.pagos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.util.Map;

import org.junit.jupiter.api.Test;

class WalletsTest {

	private final Wallets wallets = new Wallets(Map.of("ana", new BigDecimal("100")));

	@Test
	void cobraSiHaySaldo() {
		assertTrue(wallets.charge("P-1", "ana", new BigDecimal("60")).accepted());
		assertEquals(new BigDecimal("40"), wallets.balanceOf("ana").orElseThrow());
	}

	@Test
	void rechazaSiNoHaySaldo() {
		assertFalse(wallets.charge("P-1", "ana", new BigDecimal("150")).accepted());
		assertEquals(new BigDecimal("100"), wallets.balanceOf("ana").orElseThrow());
	}

	@Test
	void unMensajeDuplicadoNoCobraDosVeces() {
		wallets.charge("P-1", "ana", new BigDecimal("60"));
		assertTrue(wallets.charge("P-1", "ana", new BigDecimal("60")).accepted());
		assertEquals(new BigDecimal("40"), wallets.balanceOf("ana").orElseThrow());
	}
}
