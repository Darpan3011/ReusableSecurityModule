package com.darpan.security.config;

import com.darpan.security.filter.JwtAuthFilter;
import com.darpan.security.jwt.JwtTokenProvider;
import com.darpan.security.properties.SecurityProperties;
import com.darpan.security.repository.RoleRepository;
import com.darpan.security.repository.TokenRepository;
import com.darpan.security.repository.UserRepository;
import com.darpan.security.service.AuthService;
import com.darpan.security.service.MfaService;
import com.darpan.security.service.TokenService;
import com.darpan.security.serviceimpl.AuthServiceImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityProperties.class)
public class JwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenProvider jwtTokenProvider(SecurityProperties props, UserRepository userRepository) {
        return new JwtTokenProvider(props, userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtTokenProvider provider, TokenService tokenService, SecurityProperties props) {
        return new JwtAuthFilter(provider, tokenService, props);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthService authService(UserRepository userRepo, TokenRepository tokenRepo, PasswordEncoder encoder, JwtTokenProvider tokenProvider, RoleRepository roleRepository, MfaService mfaService) {
        return new AuthServiceImpl(userRepo, tokenRepo, encoder, tokenProvider, roleRepository, mfaService);
    }
}
