package es.codeurjc.dad.eventos.ejem3.facturacion;

import org.springframework.data.jpa.repository.JpaRepository;

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {

	long countByOrderId(String orderId);
}
