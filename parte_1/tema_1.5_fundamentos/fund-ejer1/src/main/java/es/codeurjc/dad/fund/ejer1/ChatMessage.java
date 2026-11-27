package es.codeurjc.dad.fund.ejer1;

/** Mensaje del chat: quién lo envía, el texto y el reloj vectorial del emisor al enviarlo. */
public record ChatMessage(int sender, String text, VectorClock clock) {
}
