# Security Module

## Overview
The Security Module is a comprehensive Spring Boot starter that provides robust authentication and authorization mechanisms. It includes JWT-based authentication, OAuth2 support (Google, GitHub, Azure), Multi-Factor Authentication (MFA), and role-based access control.

## Features
- **Authentication:** JWT (JSON Web Tokens) with refresh token rotation.
- **OAuth2 Support:** Built-in integration for Google, GitHub, and Azure Login.
- **Multi-Factor Authentication (MFA):** Supports Email and SMS (Twilio) verification.
- **Authorization:** Role-Based Access Control (RBAC) and Method-Level Security.
- **Security Best Practices:** Configurable CORS, Password strength validation, and secure password hashing.

How to use this as a dependency in the project?

First download the GitHub repository and do mvn clean install (so jar will be created in the .m2 location)

Add in the parent project’s pom.xml file:

```xml
<dependency>
    <groupId>com.darpan</groupId>
    <artifactId>darpan-security-starter</artifactId>
    <version>2.0.0</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
    <version>8.0.33</version>
    <scope>runtime</scope>
</dependency>
```

Allow `@ComponentScan` in parent project’s main class

```java
@EntityScan("com.darpan.security.model")
@EnableJpaRepositories("com.darpan.security.repository")
@ComponentScan(basePackages = {
        "com.darpan.security",
        "com.darpan.communication"
})
@EnableMethodSecurity
@EnableScheduling
```

Add in properties or yml file in the parent project:

Setup database connectivity with spring datasource (url, username, password etc.)

Updates properties related to CORS, endpoints that need to be public, role-based endpoints pattern authorization, OAUTH2 secrets, password pattern and its message, mail and sms provider details for MFA codes.

```properties
# MySQL Database Configuration
spring.datasource.url=
spring.datasource.username=
spring.datasource.password=
spring.datasource.driver-class-name=

# JPA/Hibernate Configuration
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=false
spring.jpa.properties.hibernate.format_sql=
spring.jpa.properties.hibernate.dialect=
spring.jpa.properties.hibernate.jdbc.time_zone=

security.cors.enabled=
security.cors.allowed-origins=
security.cors.allowed-methods=
security.cors.allowed-headers=
security.cors.exposed-headers=
security.cors.allow-credentials=
security.cors.max-age=

// keep the below listed endpoints public based on the controller given below to work the flow as expected.
security.public-endpoints[0]=/auth/register
security.public-endpoints[1]=/auth/login
security.public-endpoints[2]=/auth/refresh
security.public-endpoints[3]=/auth/auth-type
security.public-endpoints[4]=/auth/verify-email
security.public-endpoints[5]=/auth/verify-mfa
security.public-endpoints[6]=/auth/resend-code
security.public-endpoints[7]=/auth/send-mfa-code
security.public-endpoints[8]=/auth/forgot-password

security.public-endpoints[9]=/auth/reset-password
security.csrf.enabled=

# JWT secret
security.jwt-secret=
security.jwt-expiration-seconds=
security.refresh-token-expiration-seconds=

security.role-endpoints[0].pattern=/admin/**
security.role-endpoints[0].roles=ADMIN,MANAGER,GITHUB_ADMIN

security.role-endpoints[1].pattern=/user/**
security.role-endpoints[1].roles=USER,OIDC_USER,GITHUB_USER

# for github
spring.security.oauth2.client.registration.github.client-id=
spring.security.oauth2.client.registration.github.client-secret=
spring.security.oauth2.client.registration.github.scope=
spring.security.oauth2.client.registration.github.client-name=

# for google
spring.security.oauth2.client.registration.google.client-id=
spring.security.oauth2.client.registration.google.client-secret=
spring.security.oauth2.client.registration.google.scope=
spring.security.oauth2.client.registration.google.redirect-uri=
spring.security.oauth2.client.provider.google.issuer-uri=
spring.security.oauth2.client.registration.google.client-name=

# for azure
spring.security.oauth2.client.registration.azure.client-id=
spring.security.oauth2.client.registration.azure.client-secret=
spring.security.oauth2.client.registration.azure.scope=
spring.security.oauth2.client.registration.azure.redirect-uri=
spring.security.oauth2.client.registration.azure.authorization-grant-type=
spring.security.oauth2.client.registration.azure.client-name=

# Explicit endpoints for multitenant + personal accounts
spring.security.oauth2.client.provider.azure.authorization-uri=
spring.security.oauth2.client.provider.azure.token-uri=
spring.security.oauth2.client.provider.azure.user-info-uri=
spring.security.oauth2.client.provider.azure.jwk-set-uri=
spring.security.oauth2.client.provider.azure.user-name-attribute=

security.jwt.register.password.pattern=^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$
security.jwt.register.password.message=Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.

#----- Mail Configuration for MFA -----
# Gmail provider
messaging.mail.enabled=true
messaging.mail.host=
messaging.mail.port=
messaging.mail.username= // email
messaging.mail.password= // app password
messaging.mail.starttls=
messaging.mail.auth=
messaging.mail.debug=

#twilio // if using twilio for verification
messaging.twilio.enabled=true
messaging.twilio.sid=TWILIO_SID
messaging.twilio.token=TWILIO_TOKEN
messaging.twilio.from="+1659218253"
```

Define Controllers in the parents' project

### Auth Controller

```java
import com.darpan.security.model.User;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final MfaService mfaService;

    /**
     * Register a new user
     * @param user Registration request details
     * @return Response entity with status and message
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest user) {
        model.com.darpan.security.User registeredUser = authService.register(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "message", "User registered successfully. Please check your email for verification code.",
                "userId", registeredUser.getId()
        ));
    }

    /**
     * Authenticate user and return tokens
     * @param request Login request details
     * @return Response entity with tokens or error message
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            AuthResponse response = authService.login(request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            String message = e.getMessage();

            // Handle EMAIL_NOT_VERIFIED exception
            if (message.startsWith("EMAIL_NOT_VERIFIED:")) {
                Long userId = Long.parseLong(message.split(":")[1]);
                return ResponseEntity.status(403).body(Map.of(
                        "error", "EMAIL_NOT_VERIFIED",
                        "message", "Please verify your email before logging in",
                        "userId", userId
                ));
            }

            // Handle MFA_REQUIRED exception
            if (message.startsWith("MFA_REQUIRED:")) {
                String[] parts = message.split(":");
                Long userId = Long.parseLong(parts[1]);
                String[] methods = parts.length > 2 ? parts[2].split(",") : new String[]{"EMAIL"};
                String maskedEmail = parts.length > 3 ? parts[3] : "";
                String maskedPhone = parts.length > 4 ? parts[4] : "";

                return ResponseEntity.status(202).body(Map.of(
                        "mfaRequired", true,
                        "message", "Please select a verification method",
                        "userId", userId,
                        "availableMethods", methods,
                        "maskedEmail", maskedEmail,
                        "maskedPhone", maskedPhone
                ));
            }

            // Handle other exceptions
            return ResponseEntity.status(401).body(Map.of("error", message));
        }
    }

    /**
     * Send MFA code for login verification
     * @param request Request containing userId and method
     * @return Response entity with success message or error
     */
    @PostMapping("/send-mfa-code")
    public ResponseEntity<?> sendMfaCode(@RequestBody Map<String, Object> request) {
        try {
            Long userId = Long.parseLong(request.get("userId").toString());
            String methodStr = (String) request.get("method");
            MfaDeliveryMethod method = MfaDeliveryMethod.valueOf(methodStr);

            mfaService.generateAndSendCode(userId, MfaCodeType.LOGIN, method);

            return ResponseEntity.ok(Map.of(
                    "message", "Verification code sent via " + method
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // logout handled by Spring Security /logout endpoint

    /**
     * Refresh access token using refresh token
     * @param refreshToken Refresh token string
     * @return Response entity with new tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestParam("token") String refreshToken) {
        try {
            AuthResponse response = authService.refresh(refreshToken);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    /**
     * Get current authenticated user details
     * @param authentication Authentication object
     * @return Response entity with user details
     */
    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        CurrentUser user = resolveCurrentUser(authentication);
        if (user == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        return ResponseEntity.ok(user);
    }

    /**
     * Change password for the current user
     * @param req Change password request details
     * @return Response entity with success message
     */
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest req) {
        authService.changePassword(req);
        return ResponseEntity.ok("Password updated");
    }

    /**
     * Get the authentication type configured
     * @return Response entity with auth type
     */
    @GetMapping("/auth-type")
    public ResponseEntity<Map<String, String>> authType() {
        return ResponseEntity.ok(Map.of("Auth Type", authService.getAuthType().name()));
    }

    /**
     * Initiate password reset process
     * @param request Request containing email
     * @return Response entity with success message or error
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            authService.forgotPassword(email);
            return ResponseEntity.ok(Map.of("message", "Password reset code sent to your email"));
        } catch (Exception e) {
            log.error("Forgot password failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Reset password using verification code
     * @param request Request containing email, code, and newPassword
     * @return Response entity with success message or error
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            String code = request.get("code");
            String newPassword = request.get("newPassword");

            authService.resetPassword(email, code, newPassword);
            return ResponseEntity.ok(Map.of("message", "Password reset successfully. You can now login with your new password."));
        } catch (Exception e) {
            log.error("Reset password failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
```

### MFA Controller

```java
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class MfaController {
    private final MfaService mfaService;

    /**
     * Verify email address using the verification code
     * @param request Request containing userId and code
     * @return Response entity with success message or error
     */
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestBody Map<String, Object> request) {
        try {
            Long userId = Long.valueOf(request.get("userId").toString());
            String code = request.get("code").toString();

            mfaService.verifyEmailAndActivate(userId, code);
            return ResponseEntity.ok(Map.of("message", "Email verified successfully. You can now log in."));
        } catch (Exception e) {
            log.error("Email verification failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Verify MFA code for login and generate tokens
     * @param request Request containing userId and code
     * @return Response entity with auth tokens or error
     */
    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(@RequestBody Map<String, Object> request) {
        try {
            Long userId = Long.valueOf(request.get("userId").toString());
            String code = request.get("code").toString();

            AuthResponse authResponse = mfaService.verifyMfaAndGenerateTokens(userId, code);
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            log.error("MFA verification failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Resend verification code
     * @param request Request containing userId and type
     * @return Response entity with success message or error
     */
    @PostMapping("/resend-code")
    public ResponseEntity<?> resendCode(@RequestBody Map<String, Object> request) {
        try {
            Long userId = Long.valueOf(request.get("userId").toString());
            String typeStr = request.get("type").toString();
            MfaCodeType type = MfaCodeType.valueOf(typeStr);

            mfaService.resendCode(userId, type);
            return ResponseEntity.ok(Map.of("message", "Code sent successfully"));
        } catch (Exception e) {
            log.error("Resend code failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Toggle MFA for the current user
     * @param request Request containing enabled status
     * @param authentication Authentication object
     * @return Response entity with new MFA status or error
     */
    @PostMapping("/toggle-mfa")
    public ResponseEntity<?> toggleMfa(@RequestBody Map<String, Boolean> request, Authentication authentication) {
        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
            }

            String username = authentication.getName();
            boolean enabled = request.get("enabled");

           mfaService.toggleMfaForUser(username, enabled);

            return ResponseEntity.ok(Map.of("mfaEnabled", enabled, "message", "MFA " + (enabled ? "enabled" : "disabled") + " successfully"));
        } catch (Exception e) {
            log.error("Toggle MFA failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
```

### Profile Controller

```java
@Slf4j
@RestController
@RequestMapping("/profile")
@RequiredArgsConstructor
public class ProfileController {
    private final MfaService mfaService;

    /**
     * Set phone number for the current user
     * @param request Request containing phone number
     * @param authentication Authentication object
     * @return Response entity with success message or error
     */
    @PostMapping("/set-phone")
    public ResponseEntity<?> setPhoneNumber(@RequestBody SetPhoneRequest request, Authentication authentication) {
        try {
            CurrentUser currentUser = resolveCurrentUser(authentication);
            if (currentUser == null) {
                return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
            }

            mfaService.setPhoneNumberByUsername(currentUser.username(), request.getPhoneNumber());

            return ResponseEntity.ok(Map.of("message", "Phone number set successfully. Verification code sent via SMS."));
        } catch (Exception e) {
            log.error("Set phone number failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Verify phone number using verification code
     * @param request Request containing verification code
     * @param authentication Authentication object
     * @return Response entity with success message or error
     */
    @PostMapping("/verify-phone")
    public ResponseEntity<?> verifyPhoneNumber(@RequestBody VerifyPhoneRequest request, Authentication authentication) {
        try {
            CurrentUser currentUser = resolveCurrentUser(authentication);
            if (currentUser == null) {
                return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
            }

            boolean verified = mfaService.verifyPhoneNumberByUsername(currentUser.username(), request.getCode());

            if (verified) {
                return ResponseEntity.ok(Map.of("message", "Phone number verified successfully"));
            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "Verification failed"));
            }
        } catch (Exception e) {
            log.error("Phone verification failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Get phone status for the current user
     * @param authentication Authentication object
     * @return Response entity with phone status details
     */
    @GetMapping("/phone-status")
    public ResponseEntity<?> getPhoneStatus(Authentication authentication) {
        try {
            CurrentUser currentUser = resolveCurrentUser(authentication);
            if (currentUser == null) {
                return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
            }

            PhoneStatusResponse response = mfaService.getPhoneStatusByUsername(currentUser.username());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Get phone status failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
```