package com.darpan.security.config;

import com.darpan.communication.service.MessageService;
import com.darpan.security.properties.SecurityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.List;

@Slf4j
@Configuration
public class MfaMessagingConfiguration {

    @Bean
    @Primary
    public MessageService activeMessageService(List<MessageService> messageServices, SecurityProperties securityProperties) {
        String provider = securityProperties.getMfaProvider();
        if (provider == null || provider.isEmpty()) {
            provider = "twilio";
        }

        log.info("Selecting MFA provider: {}", provider);

        for (MessageService service : messageServices) {
            String serviceProviderId = service.getProviderId();
            if (serviceProviderId != null && serviceProviderId.equalsIgnoreCase(provider)) {
                log.info("Found matching MessageService provider: {}", serviceProviderId);
                return service;
            }
        }

        // Fail fast if not found
        throw new IllegalStateException(String.format(
            "Configured MFA provider '%s' not found. Available services: %s", 
            provider, messageServices.stream().map(MessageService::getProviderId).toList()));
    }
}
