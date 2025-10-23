package com.darpan.starter.security.serviceimpl;

import com.darpan.starter.security.model.OAuthUser;
import com.darpan.starter.security.repository.OAuthUserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

@Service
@Slf4j
public class CustomOidcUserServiceImpl extends OidcUserService {

    private final OAuthUserRepository oAuthUserRepository;

    public CustomOidcUserServiceImpl(OAuthUserRepository oAuthUserRepository) {
        this.oAuthUserRepository = oAuthUserRepository;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId(); // "google"
        Map<String, Object> attrs = oidcUser.getClaims(); // OIDC claims (sub, email, picture...)

        log.error("Provider: {}", provider);
        log.error("Attributes: {}", attrs);

        String providerUserId = String.valueOf(attrs.get("sub")); // OIDC subject
        String email = attrs.get("email") != null ? String.valueOf(attrs.get("email")) : null;
        String name = attrs.get("name") != null ? String.valueOf(attrs.get("name")) : email;
        String username = email != null ? email.split("@")[0] : providerUserId;
        String avatar = attrs.get("picture") != null ? String.valueOf(attrs.get("picture")) : null;

        oAuthUserRepository.findByProviderAndProviderUserId(provider, providerUserId)
                .map(u -> {
                    u.setUsername(username);
                    u.setName(name);
                    u.setEmail(email);
                    u.setAvatarUrl(avatar);
                    u.setLastAccess(Instant.now());
                    return oAuthUserRepository.save(u);
                })
                .orElseGet(() -> {
                    OAuthUser u = new OAuthUser();
                    u.setProvider(provider);
                    u.setProviderUserId(providerUserId);
                    u.setUsername(username);
                    u.setName(name);
                    u.setEmail(email);
                    u.setAvatarUrl(avatar);
                    u.setLastAccess(Instant.now());
                    return oAuthUserRepository.save(u);
                });

        return oidcUser;
    }
}
