package com.spring.jwttutorial.service;

import com.spring.jwttutorial.entity.RefreshEntity;
import com.spring.jwttutorial.repository.RefreshRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class RefreshService {

    private final RefreshRepository refreshRepository;

    public void addRefresh(String username, String refresh, Long expiredMs) {
        Date date = new Date(System.currentTimeMillis()+ expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    @Transactional
    public boolean updateRefresh(String username, String refresh, Long expiredMs) {
        Optional<RefreshEntity> optionalRefresh = refreshRepository.findByRefresh(refresh);

        if (optionalRefresh.isEmpty()) {
            return false;
        }

        Date date = new Date(System.currentTimeMillis()+ expiredMs);

        RefreshEntity refreshEntity = optionalRefresh.get();
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        return true;
    }


}
