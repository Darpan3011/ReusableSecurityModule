package com.darpan.starter.security.serviceimpl;

import com.communication.service.EmailService;
import com.darpan.starter.security.model.MfaCode;
import com.darpan.starter.security.model.MfaCodeType;
import com.darpan.starter.security.model.User;
import com.darpan.starter.security.properties.SecurityProperties;
import com.darpan.starter.security.repository.MfaCodeRepository;
import com.darpan.starter.security.repository.UserRepository;
import com.darpan.starter.security.service.MfaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;

@Slf4j
@Service
@RequiredArgsConstructor
public class MfaServiceImpl implements MfaService {

    @Value("${messaging.mail.username}")
    private String fromEmail;

    private final MfaCodeRepository mfaCodeRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final SecurityProperties securityProperties;

    @Override
    @Transactional
    public void generateAndSendCode(Long userId, MfaCodeType type) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Delete any existing unverified codes for this user and type
        mfaCodeRepository.findByUserIdAndTypeAndVerifiedFalse(userId, type)
                .ifPresent(mfaCodeRepository::delete);

        // Generate random code
        String code = generateRandomCode();

        // Create and save MFA code
        MfaCode mfaCode = MfaCode.builder()
                .userId(userId)
                .code(code)
                .type(type)
                .expiresAt(LocalDateTime.now().plusMinutes(securityProperties.getMfaCodeExpirationMinutes()))
                .verified(false)
                .build();

        mfaCodeRepository.save(mfaCode);

        // Send email
        sendCodeEmail(user, code, type);

        log.info("MFA code generated and sent for user {} (type: {})", userId, type);
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
}
