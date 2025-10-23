package com.darpan.starter.security.config;

import com.darpan.starter.security.properties.SecurityProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "security.oauth2", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(SecurityProperties.class)
public class OAuth2AutoConfiguration {
    // Place OAuth2 beans here. Kept minimal because oauth2 client deps are optional.
}
