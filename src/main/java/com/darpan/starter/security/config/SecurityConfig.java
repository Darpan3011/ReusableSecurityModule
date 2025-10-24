package com.darpan.starter.security.config;

import com.darpan.starter.security.eventlistener.OAuth2LoginSuccessListener;
import com.darpan.starter.security.eventlistener.OAuthLogoutHandler;
import com.darpan.starter.security.filter.JwtAuthFilter;
import com.darpan.starter.security.properties.SecurityProperties;
import com.darpan.starter.security.serviceimpl.CustomOAuth2UserServiceImpl;
import com.darpan.starter.security.serviceimpl.CustomOidcUserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private SecurityProperties props;
    @Autowired(required = false)
    private JwtAuthFilter jwtAuthFilter;

    @Bean
    @ConditionalOnProperty(prefix = "security.jwt", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {
        if (!props.isCsrfEnabled()) http.csrf(AbstractHttpConfigurer::disable);
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        if (props.getCors().isEnabled()) {
            CorsConfigurationSource source = request -> {
                CorsConfiguration c = new CorsConfiguration();
                c.setAllowCredentials(props.getCors().isAllowCredentials());
                c.addAllowedOrigin(props.getCors().getAllowedOrigins());
                c.addAllowedHeader(props.getCors().getAllowedHeaders());
                c.addAllowedMethod(props.getCors().getAllowedMethods());
                c.setMaxAge(props.getCors().getMaxAge());
                c.addExposedHeader(props.getCors().getExposedHeaders());
                return c;
            };
            http.cors(cors -> cors.configurationSource(source));
        }

        http.authorizeHttpRequests(auth -> {
            props.getPublicEndpoints().forEach(endpoint ->
                    auth.requestMatchers(endpoint).permitAll()
            );

            // Role-based endpoints
            props.getRoleEndpoints().forEach(re ->
                    auth.requestMatchers(re.getPattern())
                            .hasAnyAuthority(re.getRoles().toArray(new String[0]))
            );

            auth.anyRequest().authenticated();
        });

        if (jwtAuthFilter != null) {
            http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        }
        return http.build();
    }

    @Bean
    @ConditionalOnProperty(prefix = "security.oauth2", name = "enabled", havingValue = "true")
    public SecurityFilterChain oauth2FilterChain(HttpSecurity http, CustomOAuth2UserServiceImpl customOAuth2UserServiceImpl, CustomOidcUserServiceImpl customOidcUserServiceImpl, OAuth2LoginSuccessListener oAuthLoginSuccessHandler, OAuthLogoutHandler oAuthLogoutHandler) throws Exception {
        if (!props.isCsrfEnabled()) http.csrf(AbstractHttpConfigurer::disable);
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
        if (props.getCors().isEnabled()) http.cors(Customizer.withDefaults());

        http.authorizeHttpRequests(auth ->
                    {
                        auth.requestMatchers("/oauth2/**", "/login/oauth2/**", "/login/**", "/login/oauth/**").permitAll();

                        props.getPublicEndpoints().forEach(endpoint ->
                                auth.requestMatchers(endpoint).permitAll()
                        );

                        // Role-based endpoints
                        props.getRoleEndpoints().forEach(re ->
                                auth.requestMatchers(re.getPattern())
                                        .hasAnyAuthority(re.getRoles().toArray(new String[0]))
                        );

                        auth.anyRequest().authenticated();
                    }
                )
                .oauth2Login(o -> o.userInfoEndpoint(ui ->
                                ui.userService(customOAuth2UserServiceImpl)
                                        .oidcUserService(customOidcUserServiceImpl))
                        .defaultSuccessUrl(props.getOauth2SuccessRedirectUrl(), true)
                        .successHandler((request, response, authentication) -> {
                            // Manually handle success
                            oAuthLoginSuccessHandler.onOAuthLoginSuccess(request, authentication);
                            response.sendRedirect(props.getOauth2SuccessRedirectUrl());
                        })
                )

                .logout(l ->
                        l.logoutUrl("/logout")
                                .addLogoutHandler(oAuthLogoutHandler)
                                .invalidateHttpSession(true)
                                .clearAuthentication(true)
                                .deleteCookies("JSESSIONID"));

        return http.build();
    }
}
