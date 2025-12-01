package com.darpan.starter.security.serviceimpl;

import com.communication.model.SmsRequest;
import com.communication.service.EmailService;
import com.communication.service.MessageService;
import com.darpan.starter.security.jwt.JwtTokenProvider;
import com.darpan.starter.security.model.*;
import com.darpan.starter.security.properties.SecurityProperties;
import com.darpan.starter.security.repository.MfaCodeRepository;
import com.darpan.starter.security.repository.TokenRepository;
import com.darpan.starter.security.repository.UserRepository;
import com.darpan.starter.security.service.MfaService;
import com.darpan.starter.security.service.dto.AuthResponse;
import com.darpan.starter.security.service.dto.PhoneStatusResponse;
import com.darpan.starter.security.service.enums.MfaCodeType;
import com.darpan.starter.security.service.enums.MfaDeliveryMethod;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Random;

@Slf4j
@Service
public class MfaServiceImpl implements MfaService {

    @Value("${messaging.mail.username}")
    private String fromEmail;

    private final MfaCodeRepository mfaCodeRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final SecurityProperties securityProperties;
    private final TokenRepository tokenRepository;
    private final JwtTokenProvider tokenProvider;
    
    @Autowired(required = false)
    @Qualifier("twilioMessageService")
    private MessageService messageService;

    public MfaServiceImpl(MfaCodeRepository mfaCodeRepository, UserRepository userRepository,
                          EmailService emailService, SecurityProperties securityProperties,
                          TokenRepository tokenRepository, JwtTokenProvider tokenProvider) {
        this.mfaCodeRepository = mfaCodeRepository;
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.securityProperties = securityProperties;
        this.tokenRepository = tokenRepository;
        this.tokenProvider = tokenProvider;
    }

    @Override
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
    public void generateAndSendCode(Long userId, MfaCodeType type) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Delete any existing unverified codes for this user and type
        mfaCodeRepository.deleteByUserIdAndTypeAndVerifiedFalse(userId, type);

        // Generate random code
        String code = generateRandomCode();
        
        // Determine delivery method based on user preference
        MfaDeliveryMethod deliveryMethod = determineDeliveryMethod(user, type);

        // Create and save MFA code
        MfaCode mfaCode = MfaCode.builder()
                .userId(userId)
                .code(code)
                .type(type)
                .deliveryMethod(deliveryMethod)
                .expiresAt(LocalDateTime.now().plusMinutes(securityProperties.getMfaCodeExpirationMinutes()))
                .verified(false)
                .build();

        mfaCodeRepository.save(mfaCode);
        mfaCodeRepository.flush(); // Force immediate commit to database

        log.info("MFA code generated for user {} (type: {}, delivery: {})", userId, type, deliveryMethod);

        // Send code via appropriate channel
        try {
            if (deliveryMethod == MfaDeliveryMethod.SMS) {
                sendCodeSms(user, code, type);
                log.info("MFA code SMS sent to user {} (type: {})", userId, type);
            } else {
                sendCodeEmail(user, code, type);
                log.info("MFA code email sent to user {} (type: {})", userId, type);
            }
        } catch (Exception e) {
            log.error("Failed to send MFA code for user {}, but code was saved to database", userId, e);
            // Don't throw exception - code is already saved, user can resend if needed
        }
    }

    @Override
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
    public void generateAndSendCode(Long userId, MfaCodeType type, MfaDeliveryMethod method) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate method
        if (method == MfaDeliveryMethod.SMS) {
            if (user.getPhoneNumber() == null || !user.isPhoneNumberVerified()) {
                throw new RuntimeException("Cannot use SMS: Phone number not verified");
            }
            if (messageService == null) {
                throw new RuntimeException("Cannot use SMS: Service unavailable");
            }
        }

        // Delete any existing unverified codes for this user and type
        mfaCodeRepository.deleteByUserIdAndTypeAndVerifiedFalse(userId, type);

        // Generate random code
        String code = generateRandomCode();
        
        // Create and save MFA code
        MfaCode mfaCode = MfaCode.builder()
                .userId(userId)
                .code(code)
                .type(type)
                .deliveryMethod(method)
                .expiresAt(LocalDateTime.now().plusMinutes(securityProperties.getMfaCodeExpirationMinutes()))
                .verified(false)
                .build();

        mfaCodeRepository.save(mfaCode);
        mfaCodeRepository.flush(); // Force immediate commit to database

        log.info("MFA code generated for user {} (type: {}, delivery: {})", userId, type, method);

        // Send code via appropriate channel
        try {
            if (method == MfaDeliveryMethod.SMS) {
                sendCodeSms(user, code, type);
                log.info("MFA code SMS sent to user {} (type: {})", userId, type);
            } else {
                sendCodeEmail(user, code, type);
                log.info("MFA code email sent to user {} (type: {})", userId, type);
            }
        } catch (Exception e) {
            log.error("Failed to send MFA code for user {}, but code was saved to database", userId, e);
            // Don't throw exception - code is already saved, user can resend if needed
        }
    }

    @Override
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
    public void generateAndSendCodeWithUser(User user, MfaCodeType type) {
        // Delete any existing unverified codes for this user and type
        mfaCodeRepository.deleteByUserIdAndTypeAndVerifiedFalse(user.getId(), type);

        // Generate random code
        String code = generateRandomCode();
        
        // Determine delivery method based on user preference
        MfaDeliveryMethod deliveryMethod = determineDeliveryMethod(user, type);

        // Create and save MFA code
        MfaCode mfaCode = MfaCode.builder()
                .userId(user.getId())
                .code(code)
                .type(type)
                .deliveryMethod(deliveryMethod)
                .expiresAt(LocalDateTime.now().plusMinutes(securityProperties.getMfaCodeExpirationMinutes()))
                .verified(false)
                .build();

        mfaCodeRepository.save(mfaCode);
        mfaCodeRepository.flush(); // Force immediate commit to database

        log.info("MFA code generated for user {} (type: {}, delivery: {})", user.getId(), type, deliveryMethod);

        // Send code via appropriate channel
        try {
            if (deliveryMethod == MfaDeliveryMethod.SMS) {
                sendCodeSms(user, code, type);
                log.info("MFA code SMS sent to user {} (type: {})", user.getId(), type);
            } else {
                sendCodeEmail(user, code, type);
                log.info("MFA code email sent to user {} (type: {})", user.getId(), type);
            }
        } catch (Exception e) {
            log.error("Failed to send MFA code for user {}, but code was saved to database", user.getId(), e);
            // Don't throw exception - code is already saved, user can resend if needed
        }
    }

    @Override
    @Transactional
    public boolean verifyCode(Long userId, String code, MfaCodeType type) {
        MfaCode mfaCode = mfaCodeRepository.findByUserIdAndTypeAndVerifiedFalse(userId, type)
                .orElseThrow(() -> new RuntimeException("No valid code found"));

        // Check if code matches
        if (!mfaCode.getCode().equals(code)) {
            throw new RuntimeException("Invalid code");
        }

        // Check if code is expired
        if (mfaCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Code has expired");
        }

        // Mark as verified
        mfaCode.setVerified(true);
        mfaCodeRepository.save(mfaCode);

        // If this is a registration code, mark email as verified
        if (type == MfaCodeType.REGISTRATION) {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user.setEmailVerified(true);
            user.setEnabled(true); // Enable the account
            userRepository.save(user);
        }

        log.info("MFA code verified for user {} (type: {})", userId, type);
        return true;
    }

    @Override
    @Transactional
    public void resendCode(Long userId, MfaCodeType type) {
        // Simply generate a new code (old one will be deleted)
        generateAndSendCode(userId, type);
    }

    @Override
    @Transactional
    public void toggleMfa(Long userId, boolean enabled) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        user.setMfaEnabled(enabled);
        userRepository.save(user);
        
        log.info("MFA {} for user {}", enabled ? "enabled" : "disabled", userId);
    }

    @Override
    @Transactional
    public boolean verifyEmailAndActivate(Long userId, String code) {
        // Verify the code
        boolean verified = verifyCode(userId, code, MfaCodeType.REGISTRATION);
        
        if (!verified) {
            throw new RuntimeException("Invalid or expired code");
        }
        
        return true;
    }

    @Override
    @Transactional
    public AuthResponse verifyMfaAndGenerateTokens(Long userId, String code) {
        // Verify the MFA code
        boolean verified = verifyCode(userId, code, MfaCodeType.LOGIN);
        
        if (!verified) {
            throw new RuntimeException("Invalid or expired code");
        }

        // Get user
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Deactivate old tokens
        tokenRepository.deactivateOldTokens(userId);

        // Generate new tokens
        String access = tokenProvider.generateAccessToken(user.getUsername(), user.getId());
        String refresh = tokenProvider.generateRefreshToken(user.getUsername(), user.getId());

        // Save token
        Token token = new Token();
        token.setUserId(user.getId());
        token.setAccessToken(access);
        token.setRefreshToken(refresh);
        token.setAccessTokenExpiry(Instant.now().plusMillis(tokenProvider.getAccessExpiryMillis()));
        token.setRefreshTokenExpiry(Instant.now().plusMillis(tokenProvider.getRefreshExpiryMillis()));
        token.setActive(true);

        tokenRepository.save(token);

        log.info("MFA verified and tokens generated for user {}", userId);

        return new AuthResponse(access, refresh, tokenProvider.getAccessExpiryMillis() / 1000);
    }

    @Override
    @Transactional
    public void toggleMfaForUser(String username, boolean enabled) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        user.setMfaEnabled(enabled);
        userRepository.save(user);
        
        log.info("MFA {} for user {}", enabled ? "enabled" : "disabled", username);
    }

    @Override
    @Transactional
    @Scheduled(cron = "0 0 * * * *") // Run every hour
    public void cleanupExpiredCodes() {
        mfaCodeRepository.deleteByExpiresAtBefore(LocalDateTime.now());
        log.debug("Cleaned up expired MFA codes");
    }

    private String generateRandomCode() {
        Random random = new Random();
        int codeLength = securityProperties.getMfaCodeLength();
        int bound = (int) Math.pow(10, codeLength);
        int code = random.nextInt(bound);
        return String.format("%0" + codeLength + "d", code);
    }

    private void sendCodeEmail(User user, String code, MfaCodeType type) {
        String subject;
        String body;

        if (type == MfaCodeType.REGISTRATION) {
            subject = "Verify Your Email Address";
            body = buildEmailBody(
                    user.getUsername(),
                    "Thank you for registering!",
                    "Please verify your email address by entering the following code:",
                    code,
                    "This code will expire in " + securityProperties.getMfaCodeExpirationMinutes() + " minutes."
            );
        } else {
            subject = "Your Login Verification Code";
            body = buildEmailBody(
                    user.getUsername(),
                    "Login Verification Required",
                    "Please enter the following code to complete your login:",
                    code,
                    "This code will expire in " + securityProperties.getMfaCodeExpirationMinutes() + " minutes."
            );
        }

        try {
            emailService.sendEmail(user.getEmail(), subject, body, fromEmail, subject, null);
        } catch (Exception e) {
            log.error("Failed to send MFA code email to {}", user.getEmail(), e);
            throw new RuntimeException("Failed to send verification email");
        }
    }

    private String buildEmailBody(String username, String title, String message, String code, String footer) {
        return String.format("""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
                        .content { background-color: #f9f9f9; padding: 30px; border-radius: 5px; margin-top: 20px; }
                        .code { font-size: 32px; font-weight: bold; color: #4CAF50; text-align: center; letter-spacing: 5px; padding: 20px; background-color: #fff; border: 2px dashed #4CAF50; margin: 20px 0; }
                        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #777; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>%s</h1>
                        </div>
                        <div class="content">
                            <p>Hello %s,</p>
                            <p>%s</p>
                            <div class="code">%s</div>
                            <p>%s</p>
                            <p>If you didn't request this code, please ignore this email.</p>
                        </div>
                        <div class="footer">
                            <p>This is an automated message, please do not reply.</p>
                        </div>
                    </div>
                </body>
                </html>
                """, title, username, message, code, footer);
    }

    private void sendCodeSms(User user, String code, MfaCodeType type) {
        if (messageService == null) {
            log.warn("MessageService not available, falling back to email for user {}", user.getId());
            sendCodeEmail(user, code, type);
            return;
        }

        if (user.getPhoneNumber() == null || user.getPhoneNumber().trim().isEmpty()) {
            log.warn("Phone number not set for user {}, falling back to email", user.getId());
            sendCodeEmail(user, code, type);
            return;
        }

        String message;
        if (type == MfaCodeType.REGISTRATION) {
            message = String.format("Your email verification code is: %s. This code will expire in %d minutes.",
                    code, securityProperties.getMfaCodeExpirationMinutes());
        } else if (type == MfaCodeType.PHONE_VERIFICATION) {
            message = String.format("Your phone verification code is: %s. This code will expire in %d minutes.",
                    code, securityProperties.getMfaCodeExpirationMinutes());
        } else {
            message = String.format("Your login verification code is: %s. This code will expire in %d minutes.",
                    code, securityProperties.getMfaCodeExpirationMinutes());
        }

        try {
            SmsRequest smsRequest = SmsRequest.builder()
                    .to(user.getPhoneNumber())
                    .message(message)
                    .build();
            messageService.sendMessage(smsRequest);
        } catch (Exception e) {
            log.error("Failed to send MFA code SMS to {}", user.getPhoneNumber(), e);
            throw new RuntimeException("Failed to send verification SMS");
        }
    }

    private MfaDeliveryMethod determineDeliveryMethod(User user, MfaCodeType type) {
        // Phone verification always uses SMS
        if (type == MfaCodeType.PHONE_VERIFICATION) {
            return MfaDeliveryMethod.SMS;
        }

        // For other types, check user preference
        if (user.getMfaDeliveryMethod() == MfaDeliveryMethod.SMS) {
            // Only use SMS if phone number is verified and MessageService is available
            if (user.isPhoneNumberVerified() && user.getPhoneNumber() != null && messageService != null) {
                return MfaDeliveryMethod.SMS;
            } else {
                log.warn("User {} prefers SMS but phone not verified or SMS service unavailable, using email", user.getId());
                return MfaDeliveryMethod.EMAIL;
            }
        }

        return MfaDeliveryMethod.EMAIL;
    }

    @Override
    @Transactional
    public void setPhoneNumber(Long userId, String phoneNumber) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Update phone number and mark as unverified
        user.setPhoneNumber(phoneNumber);
        user.setPhoneNumberVerified(false);
        userRepository.save(user);

        log.info("Phone number set for user {}, sending verification code", userId);

        // Generate and send verification code via SMS
        generateAndSendCode(userId, MfaCodeType.PHONE_VERIFICATION);
    }

    @Override
    @Transactional
    public boolean verifyPhoneNumber(Long userId, String code) {
        // Verify the code
        boolean verified = verifyCode(userId, code, MfaCodeType.PHONE_VERIFICATION);

        if (!verified) {
            throw new RuntimeException("Invalid or expired code");
        }

        // Mark phone number as verified
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setPhoneNumberVerified(true);
        userRepository.save(user);

        log.info("Phone number verified for user {}", userId);
        return true;
    }

    @Override
    @Transactional
    public void setMfaDeliveryMethod(Long userId, MfaDeliveryMethod method) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate that phone is verified if SMS is selected
        if (method == MfaDeliveryMethod.SMS) {
            if (user.getPhoneNumber() == null || !user.isPhoneNumberVerified()) {
                throw new RuntimeException("Phone number must be verified before enabling SMS MFA");
            }
            if (messageService == null) {
                throw new RuntimeException("SMS service is not available");
            }
        }

        user.setMfaDeliveryMethod(method);
        userRepository.save(user);

        log.info("MFA delivery method set to {} for user {}", method, userId);
    }

    @Override
    public MfaDeliveryMethod getMfaDeliveryMethod(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return user.getMfaDeliveryMethod();
    }

    @Override
    @Transactional
    public void setPhoneNumberByUsername(String username, String phoneNumber) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        setPhoneNumber(user.getId(), phoneNumber);
    }

    @Override
    @Transactional
    public boolean verifyPhoneNumberByUsername(String username, String code) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return verifyPhoneNumber(user.getId(), code);
    }

    @Override
    @Transactional
    public void setMfaDeliveryMethodByUsername(String username, MfaDeliveryMethod method) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        setMfaDeliveryMethod(user.getId(), method);
    }

    @Override
    public PhoneStatusResponse getPhoneStatusByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        return PhoneStatusResponse.builder()
                .phoneNumber(user.getPhoneNumber() != null ? maskPhoneNumber(user.getPhoneNumber()) : null)
                .phoneNumberVerified(user.isPhoneNumberVerified())
                .mfaDeliveryMethod(user.getMfaDeliveryMethod())
                .mfaEnabled(user.isMfaEnabled())
                .build();
    }

    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return phoneNumber;
        }
        // Show only last 4 digits
        int visibleDigits = 4;
        String lastDigits = phoneNumber.substring(phoneNumber.length() - visibleDigits);
        return "***-***-" + lastDigits;
    }
}
