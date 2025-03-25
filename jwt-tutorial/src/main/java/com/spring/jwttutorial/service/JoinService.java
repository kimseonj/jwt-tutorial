package com.spring.jwttutorial.service;

import com.spring.jwttutorial.dto.JoinDto;
import com.spring.jwttutorial.entity.UserEntity;
import com.spring.jwttutorial.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public String joinProcess(JoinDto joinDto) {
        // 아이디 존재 확인
        boolean isExist = userRepository.existsByUsername(joinDto.getUsername());
        if (isExist) {
            return "join Fail - Exist id";
        }

        try {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(joinDto.getUsername());
            userEntity.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
            userEntity.setRole("ROLE_ADMIN");

            userRepository.save(userEntity);

            return "join Success";
        } catch (Exception e) {
            return "join Fail";
        }
    }
}
