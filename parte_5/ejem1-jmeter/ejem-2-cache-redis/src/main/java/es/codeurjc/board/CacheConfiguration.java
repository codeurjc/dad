package es.codeurjc.board;

import java.time.Duration;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

@Configuration
@EnableCaching
public class CacheConfiguration {

	@Bean
	public RedisCacheConfiguration redisCacheManager() {
		return RedisCacheConfiguration.defaultCacheConfig()
		          .entryTtl(Duration.ofMinutes(10)) // Los productos viven 10 min en caché
		          .disableCachingNullValues()
		          .serializeValuesWith(RedisSerializationContext.SerializationPair
		            .fromSerializer(new GenericJackson2JsonRedisSerializer()));	}
}
