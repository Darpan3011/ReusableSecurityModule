package com.darpan.starter.security.config;

import com.darpan.starter.security.filter.JwtAuthFilter;
import com.darpan.starter.security.jwt.JwtTokenProvider;
import com.darpan.starter.security.properties.SecurityProperties;
import com.darpan.starter.security.repository.RoleRepository;
import com.darpan.starter.security.repository.TokenRepository;
import com.darpan.starter.security.repository.UserRepository;
import com.darpan.starter.security.service.AuthService;
import com.darpan.starter.security.service.TokenService;
import com.darpan.starter.security.serviceimpl.AuthServiceImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "security.jwt", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(SecurityProperties.class)
public class JwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenProvider jwtTokenProvider(SecurityProperties props) {
        return new JwtTokenProvider(props);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthFilter jwtAuthFilter(JwtTokenProvider provider, TokenService tokenService) {
        return new JwtAuthFilter(provider, tokenService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthService authService(UserRepository userRepo, TokenRepository tokenRepo, PasswordEncoder encoder, JwtTokenProvider tokenProvider, RoleRepository roleRepository) {
        return new AuthServiceImpl(userRepo, tokenRepo, encoder, tokenProvider, roleRepository);
    }
}
