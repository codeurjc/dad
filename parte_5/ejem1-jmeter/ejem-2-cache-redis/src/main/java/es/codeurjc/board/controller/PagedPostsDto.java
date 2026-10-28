package es.codeurjc.board.controller;

import java.util.List;

import es.codeurjc.board.model.Post;

public record PagedPostsDto(List<PostDto> posts, int page, int size, long totalElements, int totalPages) {

}
