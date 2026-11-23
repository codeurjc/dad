package es.codeurjc.dad.micro.ejer1.libros;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * <pre>
 * GET  /books
 * GET  /books/{isbn}
 * POST /books/{isbn}/checkout   un ejemplar menos disponible (409 si no quedan)
 * POST /books/{isbn}/return     un ejemplar más disponible
 * </pre>
 */
@RestController
@RequestMapping("/books")
public class BookController {

	private final BookRepository books;

	public BookController(BookRepository books) {
		this.books = books;
	}

	@GetMapping
	public List<Book> all() {
		return books.findAll();
	}

	@GetMapping("/{isbn}")
	public Book one(@PathVariable String isbn) {
		return find(isbn);
	}

	@PostMapping("/{isbn}/checkout")
	@Transactional
	public Book checkout(@PathVariable String isbn) {
		Book book = find(isbn);
		book.checkout();
		return book;
	}

	@PostMapping("/{isbn}/return")
	@Transactional
	public Book giveBack(@PathVariable String isbn) {
		Book book = find(isbn);
		book.giveBack();
		return book;
	}

	private Book find(String isbn) {
		return books.findById(isbn).orElseThrow(() -> new BookNotFoundException(isbn));
	}

	@ExceptionHandler(BookNotFoundException.class)
	@ResponseStatus(HttpStatus.NOT_FOUND)
	public String notFound(BookNotFoundException e) {
		return e.getMessage();
	}

	@ExceptionHandler(IllegalStateException.class)
	@ResponseStatus(HttpStatus.CONFLICT)
	public String conflict(IllegalStateException e) {
		return e.getMessage();
	}

	public static class BookNotFoundException extends RuntimeException {

		public BookNotFoundException(String isbn) {
			super("No existe el libro " + isbn);
		}
	}
}
