package com.example.interact.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

@Service
public class ActiveUserService {

    @Value("app.redis.keys.active-users")
    private String activeUsersRedisKey;

    private final RedisTemplate<String, Object> redisTemplate;

    public ActiveUserService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void addActiveUser(UUID uuid) {
        redisTemplate.opsForSet().add(activeUsersRedisKey, uuid);
    }

    public void removeActiveUser(UUID uuid) {
        redisTemplate.opsForSet().remove(activeUsersRedisKey, uuid);
    }

    public Set<Object> getAllActiveUsers() {
        return redisTemplate.opsForSet().members(activeUsersRedisKey);
    }

}
