package com.darpan.starter.security.serviceimpl;

import com.darpan.starter.security.model.OAuthUser;
import com.darpan.starter.security.repository.OAuthUserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.Map;

@Service
@Slf4j
public class CustomOAuth2UserServiceImpl extends DefaultOAuth2UserService {

    private final OAuthUserRepository oAuthUserRepository;

    public CustomOAuth2UserServiceImpl(OAuthUserRepository oAuthUserRepository) {
        this.oAuthUserRepository = oAuthUserRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId(); // "github"
        Map<String, Object> a = oauth2User.getAttributes();

        String providerUserId;
        String username;
        String name;
        String email;
        String avatar;
        if ("github".equalsIgnoreCase(provider)) {
            providerUserId = String.valueOf(a.get("id"));
            username = String.valueOf(a.get("login"));
            name = a.get("name") != null ? String.valueOf(a.get("name")) : username;
            email = a.get("email") != null ? String.valueOf(a.get("email")) : null;
            avatar = a.get("avatar_url") != null ? String.valueOf(a.get("avatar_url")) : null;
        }
        else if ("google".equalsIgnoreCase(provider)) {
            providerUserId = String.valueOf(a.get("sub"));
            email = String.valueOf(a.get("email"));
            name = a.get("name") != null ? String.valueOf(a.get("name")) : email;
            username = email != null ? email.split("@")[0] : providerUserId;
            avatar = a.get("picture") != null ? String.valueOf(a.get("picture")) : null;
        }
        else {
            throw new IllegalArgumentException("Unsupported provider: " + provider);
        }

        oAuthUserRepository.findByProviderAndProviderUserId(provider, providerUserId)
                .map(u -> {
                    u.setUsername(username);
                    u.setName(name);
                    u.setEmail(email);
                    u.setAvatarUrl(avatar);
                    u.setLastAccess(OffsetDateTime.now());
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
                    u.setLastAccess(OffsetDateTime.now());
                    return oAuthUserRepository.save(u);
                });

        return oauth2User;
    }
}
