package es.codeurjc.board.controller;

import java.util.List;

public record PostDto(Long id, String username, String title, String text, List<CommentDto> comments) {

}
