package es.codeurjc.board.controller;

import java.util.Map;

import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CacheController {

	private CacheManager cacheManager;
	
	public CacheController(CacheManager cacheManager) {
		this.cacheManager = cacheManager;
	}
	
	@GetMapping("/cache")
	public Map<Object, Object> getCacheContent() {
		ConcurrentMapCacheManager cacheMgr = (ConcurrentMapCacheManager) cacheManager;
		ConcurrentMapCache cache = (ConcurrentMapCache) cacheMgr.getCache("posts");
		return cache.getNativeCache();
	}
}
