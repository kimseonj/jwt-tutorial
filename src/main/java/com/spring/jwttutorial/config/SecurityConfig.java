package com.spring.jwttutorial.config;

import com.spring.jwttutorial.jwt.*;
import com.spring.jwttutorial.service.RefreshService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshService refreshService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // cors 설정
        http
                .cors(cors -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration config = new CorsConfiguration();

                                config.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                                config.setAllowedMethods(Collections.singletonList("*"));
                                config.setAllowCredentials(true);
                                config.setAllowedHeaders(Collections.singletonList("*"));
                                config.setMaxAge(360000L);

                                config.setExposedHeaders(Collections.singletonList("Authorization"));

                                return null;
                            }
                        }));

        // csrf disable
        http
                .csrf(auth -> auth.disable());

        // formLogin 방식 disable
        http
                .formLogin(auth -> auth.disable());

        // httpBasic 인증방식 disalbe
        http
                .httpBasic(auth -> auth.disable());

        /*
        // LogoutHandler 사용
        http
                .logout(auth -> auth
                        .permitAll()
                        .addLogoutHandler(new LogoutHandler(refreshService, jwtUtil)));
        */

        // LogoutFilter 사용
        http
                .logout(auth -> auth.disable());
        http
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshService), LogoutFilter.class);

        // 경로별 인가 작업
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/", "/join", "/reissue").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                );

        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // LoginFilter 등록 (필터에 /login URL 설정)
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshService), UsernamePasswordAuthenticationFilter.class);

        // session 설정 -> stateless로 변경
        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

//        // LogoutFilter 등록
//        http
//                .addFilterBefore(new LogoutFilter(refreshService, jwtUtil), LogoutFilter.class);

        return http.build();
    }

}
