package com.darpan.starter.security.config;

import com.darpan.starter.security.properties.SecurityProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "security.oauth2", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(SecurityProperties.class)
public class OAuth2AutoConfiguration {

    @Bean
    public CorsConfigurationSource corsConfigurationSource(SecurityProperties props) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(props.getCors().isAllowCredentials());
        config.setAllowedOrigins(Arrays.asList(props.getCors().getAllowedOrigins().split(",")));
        config.setAllowedMethods(Arrays.asList(props.getCors().getAllowedMethods().split(",")));
        config.setAllowedHeaders(Arrays.asList(props.getCors().getAllowedHeaders().split(",")));
        config.setExposedHeaders(Arrays.asList(props.getCors().getExposedHeaders().split(",")));
        config.setMaxAge(props.getCors().getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
