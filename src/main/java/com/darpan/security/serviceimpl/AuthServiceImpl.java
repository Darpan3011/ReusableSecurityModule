package com.darpan.security.serviceimpl;

import com.darpan.security.jwt.JwtTokenProvider;
import com.darpan.security.model.Role;
import com.darpan.security.model.Token;
import com.darpan.security.model.User;
import com.darpan.security.repository.RoleRepository;
import com.darpan.security.repository.TokenRepository;
import com.darpan.security.repository.UserRepository;
import com.darpan.security.service.AuthService;
import com.darpan.security.service.MfaService;
import com.darpan.security.service.dto.AuthResponse;
import com.darpan.security.service.dto.ChangePasswordRequest;
import com.darpan.security.service.dto.LoginRequest;
import com.darpan.security.service.dto.LoginResult;
import com.darpan.security.service.dto.MfaRequiredResponse;
import com.darpan.security.service.dto.RegisterRequest;
import com.darpan.security.service.enums.AuthEnum;
import com.darpan.security.service.enums.MfaCodeType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.regex.Pattern;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    @Value("${security.jwt.register.password.pattern}")
    private String passwordPattern;

    @Value("${security.jwt.register.password.message:Follow valid password pattern}")
    private String passwordPatternMessage;

    // Toggles removed - both enabled by default

    private final UserRepository userRepo;
    private final TokenRepository tokenRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final RoleRepository roleRepo;
    private final MfaService mfaService;

    public AuthServiceImpl(UserRepository userRepo, TokenRepository tokenRepo, PasswordEncoder passwordEncoder, JwtTokenProvider tokenProvider, RoleRepository roleRepository, MfaService mfaService) {
        this.userRepo = userRepo;
        this.tokenRepo = tokenRepo;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
        this.roleRepo = roleRepository;
        this.mfaService = mfaService;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public User register(RegisterRequest req) {
        if (!Pattern.matches(passwordPattern, req.getPassword())) throw new RuntimeException(passwordPatternMessage);
        if (userRepo.findByUsername(req.getUsername()).isPresent()) throw new RuntimeException("Username already exists");
        if (userRepo.findByEmail(req.getEmail()).isPresent()) throw new RuntimeException("Email already exists");
        Role defaultRole = roleRepo.findByName("USER").orElseGet(() -> roleRepo.save(new Role("USER")));
        User u = new User();
        u.setUsername(req.getUsername());
        u.setEmail(req.getEmail());
        u.setPassword(passwordEncoder.encode(req.getPassword()));
        u.setRoles(new HashSet<>(Collections.singleton(defaultRole))); // defaultRole = USER entity
        
        // Set account as disabled until email is verified
        u.setEnabled(false);
        u.setEmailVerified(false);
        
        User savedUser = userRepo.save(u);
        
        // Send verification email
        try {
            mfaService.generateAndSendCodeWithUser(savedUser, MfaCodeType.REGISTRATION);
        } catch (Exception e) {
            log.error("Failed to send verification email for user {}", savedUser.getId(), e);
            // Don't fail registration, but log the error
        }
        
        return savedUser;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public LoginResult login(LoginRequest req) {
        User user = userRepo.findByUsername(req.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));
        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        // Check if email is verified
        if (!user.isEmailVerified()) {
            return LoginResult.emailNotVerified(user.getId());
        }

        // Check if MFA is enabled
        if (user.isMfaEnabled()) {
            java.util.List<String> methods = new java.util.ArrayList<>();
            methods.add("EMAIL");
            if (user.isPhoneNumberVerified()) {
                methods.add("SMS");
            }

            MfaRequiredResponse mfa = MfaRequiredResponse.builder()
                    .userId(user.getId())
                    .message("Please select a verification method")
                    .mfaRequired(true)
                    .availableMethods(methods.toArray(new String[0]))
                    .maskedEmail(maskEmail(user.getEmail()))
                    .maskedPhone(maskPhoneNumber(user.getPhoneNumber()))
                    .build();
            return LoginResult.mfaRequired(mfa);
        }

        // Proceed with normal login
        tokenRepo.deactivateOldTokens(user.getId());

        String access = tokenProvider.generateAccessToken(user.getUsername(), user.getId());
        String refresh = tokenProvider.generateRefreshToken(user.getUsername(), user.getId());

        Token token = new Token();
        token.setUserId(user.getId());
        token.setAccessToken(access);
        token.setRefreshToken(refresh);
        token.setAccessTokenExpiry(Instant.now().plusMillis(tokenProvider.getAccessExpiryMillis()));
        token.setRefreshTokenExpiry(Instant.now().plusMillis(tokenProvider.getRefreshExpiryMillis()));
        token.setActive(true);
        tokenRepo.save(token);

        AuthResponse authResponse = new AuthResponse(access, refresh, tokenProvider.getAccessExpiryMillis() / 1000);
        return LoginResult.success(authResponse);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public AuthResponse refresh(String refreshToken) {
        Token oldToken = tokenRepo.findByRefreshToken(refreshToken).orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        if (!oldToken.isActive()) throw new RuntimeException("Inactive token");
        if (!tokenProvider.validateToken(refreshToken)) {
            oldToken.setActive(false);
            tokenRepo.save(oldToken);
            throw new RuntimeException("Expired refresh token");
        }

        // parse username from refresh token
        String username = tokenProvider.getUsername(refreshToken);
        Long uid = oldToken.getUserId();

        // generate new tokens
        String newAccess = tokenProvider.generateAccessToken(username, uid);
        String newRefresh = tokenProvider.generateRefreshToken(username, uid);

        // deactivate the old one
        oldToken.setActive(false);
        tokenRepo.save(oldToken);

        // create a new entry
        Token newToken = new Token();
        newToken.setUserId(uid);
        newToken.setAccessToken(newAccess);
        newToken.setRefreshToken(newRefresh);
        newToken.setAccessTokenExpiry(Instant.now().plusMillis(tokenProvider.getAccessExpiryMillis()));
        newToken.setRefreshTokenExpiry(Instant.now().plusMillis(tokenProvider.getRefreshExpiryMillis()));
        newToken.setActive(true);
        tokenRepo.save(newToken);

        return new AuthResponse(newAccess, newRefresh, tokenProvider.getAccessExpiryMillis() / 1000);
    }

    // removed empty key method; provider is the single source for JWT parsing

    /**
     * {@inheritDoc}
     */
    @Override
    public User findByUsername(String username) {
        return userRepo.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void changePassword(ChangePasswordRequest request) {
        Optional<User> maybeUser = userRepo.findByEmail(request.getEmail());
        // fail fast if user not found - avoid ambiguous behavior
        User user = maybeUser.orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        // verify current password
        boolean matches = passwordEncoder.matches(request.getCurrentPassword(), user.getPassword());
        if (!matches) {
            // you can throw a custom exception mapped to 403
            throw new IllegalArgumentException("Invalid credentials");
        }

        // optionally enforce password policy here (denylist, complexity)
        String encoded = passwordEncoder.encode(request.getNewPassword());
        user.setPassword(encoded);
        userRepo.save(user);

        if (tokenRepo != null) {
            try {
                tokenRepo.deleteByUserId(user.getId());
            } catch (Exception ignored) {
                log.error("Failed to delete tokens for user {}", user.getId());
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthEnum getAuthType() {
        return AuthEnum.BOTH;
    }

    /**
     * Mask email address for privacy
     * @param email Email to mask
     * @return Masked email string
     */
    private String maskEmail(String email) {
        if (email == null || email.isEmpty()) return "";
        int atIndex = email.indexOf("@");
        if (atIndex <= 3) return email; // too short to mask
        return "***" + email.substring(atIndex - 3); // e.g., ***321@gmail.com
    }

    /**
     * Mask phone number for privacy
     * @param phone Phone number to mask
     * @return Masked phone number string
     */
    private String maskPhoneNumber(String phone) {
        if (phone == null || phone.isEmpty()) return "";
        if (phone.length() <= 4) return phone;
        return "****" + phone.substring(phone.length() - 4); // e.g., ****7177
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void forgotPassword(String email) {
        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("No account found with this email"));
        
        // Generate and send password reset code
        mfaService.generateAndSendCodeWithUser(user, MfaCodeType.PASSWORD_RESET);
        log.info("Password reset code sent to user {}", user.getId());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void resetPassword(String email, String code, String newPassword) {
        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("No account found with this email"));
        
        // Verify the password reset code
        boolean verified = mfaService.verifyCode(user.getId(), code, MfaCodeType.PASSWORD_RESET);
        
        if (!verified) {
            throw new RuntimeException("Invalid or expired code");
        }
        
        // Validate password pattern
        if (!Pattern.matches(passwordPattern, newPassword)) {
            throw new RuntimeException(passwordPatternMessage);
        }
        
        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);
        
        // Invalidate all existing tokens
        tokenRepo.deleteByUserId(user.getId());
        
        log.info("Password reset successfully for user {}", user.getId());
    }
}
