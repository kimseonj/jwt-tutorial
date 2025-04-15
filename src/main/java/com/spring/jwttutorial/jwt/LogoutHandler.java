package com.spring.jwttutorial.jwt;

import com.spring.jwttutorial.service.RefreshService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

public class LogoutHandler implements org.springframework.security.web.authentication.logout.LogoutHandler {

    private final RefreshService refreshService;
    private final JWTUtil jwtUtil;

    public LogoutHandler(RefreshService refreshService, JWTUtil jwtUtil) {
        this.refreshService = refreshService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Cookie refreshCookie = null;
        String token = null;

        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refreshCookie = cookie;
                token = cookie.getValue();
            }
        }

        if (token == null || !jwtUtil.getCategory(token).equals("refresh")) {
            return;
        }

        String username = jwtUtil.getUsername(token);

        refreshService.removeRefresh(username);

        refreshCookie.setMaxAge(0);
        response.addCookie(refreshCookie);

        return;
    }

}
