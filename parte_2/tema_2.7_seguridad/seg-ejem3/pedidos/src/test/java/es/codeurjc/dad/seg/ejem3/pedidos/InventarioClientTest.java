package es.codeurjc.dad.seg.ejem3.pedidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Sin Keycloak ni inventario: el endpoint de tokens se sustituye por una función y
 * el inventario por MockRestServiceServer.
 */
class InventarioClientTest {

	private final AtomicInteger tokensPedidos = new AtomicInteger();
	private MockRestServiceServer inventario;
	private InventarioClient client;

	@BeforeEach
	void setUp() {
		ClientRegistration registration = ClientRegistration.withRegistrationId("inventario")
				.clientId("pedidos-service")
				.clientSecret("secreto")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.tokenUri("http://keycloak/token")
				.build();
		InMemoryClientRegistrationRepository registrations = new InMemoryClientRegistrationRepository(registration);

		// "Keycloak": cada vez que se le pide un token devuelve uno nuevo, válido 5 minutos
		OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> keycloak = request ->
				OAuth2AccessTokenResponse.withToken("token-" + tokensPedidos.incrementAndGet())
						.tokenType(OAuth2AccessToken.TokenType.BEARER)
						.expiresIn(300)
						.build();

		AuthorizedClientServiceOAuth2AuthorizedClientManager manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
				registrations, new InMemoryOAuth2AuthorizedClientService(registrations));
		manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
				.clientCredentials(cc -> cc.accessTokenResponseClient(keycloak))
				.build());

		RestClient.Builder builder = RestClient.builder();
		inventario = MockRestServiceServer.bindTo(builder).build();
		client = new InventarioClient(ClientConfig.crearInventarioRestClient(builder, manager, "http://inventario"));
	}

	@Test
	void lasLlamadasLlevanElTokenYEsteSeReutiliza() {
		inventario.expect(ExpectedCount.times(3), requestTo("http://inventario/api/stock/teclado"))
				.andExpect(header("Authorization", "Bearer token-1"))
				.andRespond(withSuccess("{\"producto\":\"teclado\",\"unidades\":10}", MediaType.APPLICATION_JSON));

		for (int i = 0; i < 3; i++) {
			assertEquals(10, client.unidades("teclado"));
		}

		inventario.verify();
		assertEquals(1, tokensPedidos.get(), "el token se pide una vez y se reutiliza hasta que caduca");
	}
}
