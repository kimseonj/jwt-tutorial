package com.spring.jwttutorial.controller;

import com.spring.jwttutorial.dto.JoinDto;
import com.spring.jwttutorial.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDto joinDto) {
        return joinService.joinProcess(joinDto);
    }
}
