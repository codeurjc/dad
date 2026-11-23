package es.codeurjc.dad.ddd.ejem3.shipping.infrastructure;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import es.codeurjc.dad.ddd.ejem3.shipping.acl.paqueexpress.PaqueExpressCarrierAdapter;
import es.codeurjc.dad.ddd.ejem3.shipping.acl.paqueexpress.PaqueExpressLegacyClient;
import es.codeurjc.dad.ddd.ejem3.shipping.domain.CarrierGateway;

@Configuration
public class ShippingConfig {

	@Bean
	CarrierGateway carrierGateway() {
		return new PaqueExpressCarrierAdapter(new PaqueExpressLegacyClient());
	}
}
