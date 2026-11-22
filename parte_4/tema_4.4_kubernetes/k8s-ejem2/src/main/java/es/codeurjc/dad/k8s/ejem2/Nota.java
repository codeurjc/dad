package es.codeurjc.dad.k8s.ejem2;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

@Entity
public class Nota {

	@Id
	@GeneratedValue
	private Long id;
	private String texto;
	/** Pod que la guardó: todas las réplicas comparten la misma base de datos */
	private String pod;

	protected Nota() {
	}

	public Nota(String texto, String pod) {
		this.texto = texto;
		this.pod = pod;
	}

	public Long getId() {
		return id;
	}

	public String getTexto() {
		return texto;
	}

	public String getPod() {
		return pod;
	}
}
