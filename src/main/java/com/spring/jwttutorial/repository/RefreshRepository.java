package com.spring.jwttutorial.repository;

import com.spring.jwttutorial.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {
    boolean existsByRefresh(String refresh);

    Optional<RefreshEntity> findByRefresh(String refresh);
}
