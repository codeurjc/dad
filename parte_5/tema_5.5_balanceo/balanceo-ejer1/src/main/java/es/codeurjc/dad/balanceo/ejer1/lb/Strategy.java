package es.codeurjc.dad.balanceo.ejer1.lb;

import java.util.List;

/**
 * Algoritmo de balanceo: elige un servidor entre los que están sanos.
 */
public interface Strategy {

	/**
	 * @param healthy  servidores sanos (nunca vacía)
	 * @param clientKey identificador del cliente (IP) para los algoritmos con afinidad
	 */
	Backend choose(List<Backend> healthy, String clientKey);
}
