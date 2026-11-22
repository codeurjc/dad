package es.codeurjc.dad.seg.ejem3.pedidos;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;

@Configuration
public class ClientConfig {

	/**
	 * Obtiene (y guarda hasta que caduca) el token del servicio. Esta implementación
	 * funciona fuera de una petición HTTP de un usuario: es la adecuada entre servicios.
	 */
	@Bean
	OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository registrations,
			OAuth2AuthorizedClientService authorizedClients) {
		AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, authorizedClients);
		manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
				.clientCredentials()
				.build());
		return manager;
	}

	@Bean
	RestClient inventarioRestClient(RestClient.Builder builder, OAuth2AuthorizedClientManager manager,
			@Value("${inventario.url}") String url) {
		return crearInventarioRestClient(builder, manager, url);
	}

	/** Cada petición sale con "Authorization: Bearer <token del servicio de pedidos>" */
	static RestClient crearInventarioRestClient(RestClient.Builder builder, OAuth2AuthorizedClientManager manager,
			String url) {
		OAuth2ClientHttpRequestInterceptor interceptor = new OAuth2ClientHttpRequestInterceptor(manager);
		interceptor.setClientRegistrationIdResolver(request -> "inventario");
		return builder.baseUrl(url).requestInterceptor(interceptor).build();
	}
}
