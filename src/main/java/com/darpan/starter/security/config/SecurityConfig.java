package com.darpan.starter.security.config;

import com.darpan.starter.security.errorhandler.JwtAccessDeniedHandler;
import com.darpan.starter.security.errorhandler.JwtAuthenticationEntryPoint;
import com.darpan.starter.security.eventlistener.OAuth2LoginSuccessListener;
import com.darpan.starter.security.eventlistener.OAuthLogoutHandler;
import com.darpan.starter.security.filter.JwtAuthFilter;
import com.darpan.starter.security.properties.SecurityProperties;
import com.darpan.starter.security.serviceimpl.CustomOAuth2UserServiceImpl;
import com.darpan.starter.security.serviceimpl.CustomOidcUserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private SecurityProperties props;
    @Autowired(required = false)
    private JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                                                   JwtAccessDeniedHandler jwtAccessDeniedHandler,
                                                   CustomOAuth2UserServiceImpl customOAuth2UserServiceImpl,
                                                   CustomOidcUserServiceImpl customOidcUserServiceImpl,
                                                   OAuth2LoginSuccessListener oAuthLoginSuccessHandler,
                                                   OAuthLogoutHandler oAuthLogoutHandler) throws Exception {

        if (!props.isCsrfEnabled()) http.csrf(AbstractHttpConfigurer::disable);
        
        // Use IF_REQUIRED to support both stateless (JWT) and stateful (OAuth2) sessions
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

        if (props.getCors().isEnabled()) {
            http.cors(Customizer.withDefaults());
        }

        http.authorizeHttpRequests(auth -> {
            auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
            
            // OAuth2 public endpoints
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
        });

        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)
        );

        // Add JWT filter
        if (jwtAuthFilter != null) {
            http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        }

        // Configure OAuth2 Login
        http.oauth2Login(o -> o
                .userInfoEndpoint(ui -> ui
                        .userService(customOAuth2UserServiceImpl)
                        .oidcUserService(customOidcUserServiceImpl))
                .defaultSuccessUrl(props.getOauth2SuccessRedirectUrl(), true)
                .successHandler((request, response, authentication) -> {
                    // Manually handle success
                    oAuthLoginSuccessHandler.onOAuthLoginSuccess(request, authentication);
                    response.sendRedirect(props.getOauth2SuccessRedirectUrl());
                })
        );

        // Configure Logout
        http.logout(l -> l
                .logoutUrl("/logout")
                .addLogoutHandler(oAuthLogoutHandler)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .logoutSuccessHandler((request, response, authentication) -> {
                    // Prevent session creation after logout
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"message\":\"Logged out successfully\"}");
                    response.getWriter().flush();
                })
        );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
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
