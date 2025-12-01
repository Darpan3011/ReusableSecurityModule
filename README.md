# 🛡️ Spring Security Starter Module

A comprehensive, production-ready security module for Spring Boot applications with support for **JWT authentication**, **OAuth2 login**, and **Multi-Factor Authentication (MFA)** via email.

---

## 🚀 Features

- ✅ **Dual Authentication Support**: JWT and OAuth2 (Google, GitHub, Microsoft) work simultaneously
- 🔐 **Multi-Factor Authentication (MFA)**: Email-based verification codes for enhanced security
- 📧 **Email Verification**: Verify user email addresses during registration
- 🔑 **JWT Token Management**: Access and refresh tokens with automatic rotation
- 🌐 **OAuth2 Integration**: Ready-to-use Google, GitHub, and Microsoft login
- ⚙️ **Configuration-Driven**: No hardcoding, fully customizable via properties
- 🧩 **CORS & CSRF Protection**: Built-in security best practices
- 🪶 **Plug-and-Play**: Works as a starter module or in multi-module projects
- 👥 **Role-Based Access Control**: Fine-grained endpoint protection

---

## 📦 Installation

### 1. Add Dependency

**If published as a JAR:**
```xml
<dependency>
  <groupId>com.darpan.starter</groupId>
  <artifactId>security</artifactId>
  <version>0.0.1</version>
</dependency>
```

**If included locally**, ensure your project recognizes the module in your multi-module build.

---

### 2. Configure Your Application

Add the following to your `application.properties`:

```properties
# ============================================
# SECURITY CONFIGURATION
# ============================================

# --- CORS Configuration ---
security.cors.enabled=true
security.cors.allowed-origins=http://localhost:3000
security.cors.allowed-methods=*
security.cors.allowed-headers=*
security.cors.exposed-headers=*
security.cors.allow-credentials=true
security.cors.max-age=3600

# --- Public Endpoints (no authentication required) ---
security.public-endpoints[0]=/auth/register
security.public-endpoints[1]=/auth/login
security.public-endpoints[2]=/auth/refresh/**
security.public-endpoints[3]=/auth/auth-type
security.public-endpoints[4]=/auth/verify-email
security.public-endpoints[5]=/auth/verify-mfa
security.public-endpoints[6]=/auth/resend-code

# --- CSRF Configuration ---
security.csrf.enabled=true

# --- JWT Configuration ---
security.jwt-secret=REPLACE_WITH_STRONG_SECRET_KEY_AT_LEAST_256_BITS
security.jwt-expiration-seconds=900
security.refresh-token-expiration-seconds=86400

# --- MFA Configuration ---
security.mfa-code-expiration-minutes=10
security.mfa-code-length=6

# --- Role-Based Access Control ---
security.role-endpoints[0].pattern=/admin/**
security.role-endpoints[0].roles=ADMIN
security.role-endpoints[1].pattern=/user/**
security.role-endpoints[1].roles=USER
```

### 3. OAuth2 Configuration (Optional)

```properties
# --- GitHub OAuth2 ---
spring.security.oauth2.client.registration.github.client-id=YOUR_GITHUB_CLIENT_ID
spring.security.oauth2.client.registration.github.client-secret=YOUR_GITHUB_CLIENT_SECRET
spring.security.oauth2.client.registration.github.scope=read:user,user:email

# --- Google OAuth2 ---
spring.security.oauth2.client.registration.google.client-id=YOUR_GOOGLE_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=YOUR_GOOGLE_CLIENT_SECRET
spring.security.oauth2.client.registration.google.scope=openid,profile,email
spring.security.oauth2.client.provider.google.issuer-uri=https://accounts.google.com

# --- Microsoft/Azure OAuth2 ---
spring.security.oauth2.client.registration.azure.client-id=YOUR_AZURE_CLIENT_ID
spring.security.oauth2.client.registration.azure.client-secret=YOUR_AZURE_CLIENT_SECRET
spring.security.oauth2.client.registration.azure.scope=openid,profile,email
spring.security.oauth2.client.registration.azure.redirect-uri={baseUrl}/login/oauth2/code/azure
spring.security.oauth2.client.provider.azure.authorization-uri=https://login.microsoftonline.com/common/oauth2/v2.0/authorize
spring.security.oauth2.client.provider.azure.token-uri=https://login.microsoftonline.com/common/oauth2/v2.0/token
spring.security.oauth2.client.provider.azure.user-info-uri=https://graph.microsoft.com/oidc/userinfo
spring.security.oauth2.client.provider.azure.jwk-set-uri=https://login.microsoftonline.com/common/discovery/v2.0/keys
spring.security.oauth2.client.provider.azure.user-name-attribute=sub
```

### 4. Email Service Configuration

MFA requires an email service. Configure your email provider:

```properties
# --- Email Configuration (for MFA codes) ---
messaging.mail.host=smtp.gmail.com
messaging.mail.port=587
messaging.mail.username=your-email@gmail.com
messaging.mail.password=your-app-password
messaging.mail.properties.mail.smtp.auth=true
messaging.mail.properties.mail.smtp.starttls.enable=true
```

> **Note**: For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833) instead of your regular password.

---

### 5. Update Your Application Class

Ensure Spring scans the security module packages:

```java
package com.test.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EntityScan("com.darpan.starter.security.model")
@EnableJpaRepositories("com.darpan.starter.security.repository")
@ComponentScan(basePackages = {
    "com.darpan.starter.security",
    "com.test.demo"  // Your application package
})
@EnableMethodSecurity
@EnableScheduling  // Required for MFA code cleanup
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
```

---

## 🔐 Authentication Flows

### 1. JWT Registration & Login (with Email Verification)

#### **Step 1: Register**
```http
POST /auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "id": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "enabled": false,
  "emailVerified": false
}
```

> User receives a 6-digit verification code via email.

#### **Step 2: Verify Email**
```http
POST /auth/verify-email
Content-Type: application/json

{
  "userId": 1,
  "code": "123456"
}
```

**Response:**
```json
{
  "message": "Email verified successfully"
}
```

#### **Step 3: Login**
```http
POST /auth/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "SecurePass123!"
}
```

**Response (if MFA is disabled):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (if MFA is enabled):**
```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "userId": 1,
  "message": "MFA code sent to your email"
}
```

> User receives a 6-digit MFA code via email.

#### **Step 4: Verify MFA Code (if MFA enabled)**
```http
POST /auth/verify-mfa
Content-Type: application/json

{
  "userId": 1,
  "code": "654321"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 2. OAuth2 Login

Simply redirect users to:
- **Google**: `http://localhost:8080/oauth2/authorization/google`
- **GitHub**: `http://localhost:8080/oauth2/authorization/github`
- **Microsoft**: `http://localhost:8080/oauth2/authorization/azure`

After successful authentication, users are redirected to your configured success URL with a session cookie.

> **Note**: MFA is **not applicable** for OAuth2 users as providers (Google, GitHub, etc.) handle their own 2FA.

---

## 🔑 API Endpoints

### Authentication Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/auth/register` | POST | Register new user | ❌ |
| `/auth/login` | POST | Login with username/password | ❌ |
| `/auth/verify-email` | POST | Verify email with code | ❌ |
| `/auth/verify-mfa` | POST | Verify MFA code during login | ❌ |
| `/auth/resend-code` | POST | Resend verification/MFA code | ❌ |
| `/auth/refresh` | POST | Refresh access token | ❌ |
| `/auth/me` | GET | Get current user info | ✅ |
| `/auth/toggle-mfa` | POST | Enable/disable MFA | ✅ |
| `/auth/change-password` | POST | Change user password | ✅ |
| `/logout` | POST | Logout (clears session) | ✅ |

### MFA Management

#### **Toggle MFA**
```http
POST /auth/toggle-mfa
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "enabled": true
}
```

**Response:**
```json
{
  "message": "MFA enabled successfully"
}
```

#### **Resend Code**
```http
POST /auth/resend-code
Content-Type: application/json

{
  "userId": 1,
  "type": "LOGIN"  // or "REGISTRATION"
}
```

**Response:**
```json
{
  "message": "Code sent successfully"
}
```

---

## 🗄️ Database Schema

The module automatically creates the following tables:

### `users`
- `id` (Primary Key)
- `username` (Unique)
- `email` (Unique)
- `password` (Hashed)
- `enabled` (Boolean)
- `email_verified` (Boolean)
- `mfa_enabled` (Boolean)
- Timestamps

### `roles`
- `id` (Primary Key)
- `name` (e.g., "USER", "ADMIN")

### `user_roles` (Join Table)
- `user_id`
- `role_id`

### `tokens`
- `id` (Primary Key)
- `user_id` (Foreign Key)
- `token` (Refresh Token)
- `active` (Boolean)
- Timestamps

### `mfa_codes`
- `id` (Primary Key)
- `user_id` (Foreign Key)
- `code` (6-digit code)
- `type` (REGISTRATION or LOGIN)
- `expires_at` (Timestamp)
- `verified` (Boolean)
- Timestamps

---

## ⚙️ Configuration Reference

### Security Properties

| Property | Default | Description |
|----------|---------|-------------|
| `security.jwt-secret` | - | Secret key for JWT signing (required) |
| `security.jwt-expiration-seconds` | 900 | Access token expiration (15 min) |
| `security.refresh-token-expiration-seconds` | 86400 | Refresh token expiration (24 hours) |
| `security.mfa-code-expiration-minutes` | 10 | MFA code validity period |
| `security.mfa-code-length` | 6 | Length of MFA codes |
| `security.cors.enabled` | false | Enable CORS |
| `security.csrf.enabled` | true | Enable CSRF protection |
| `security.public-endpoints` | [] | List of public endpoints |
| `security.role-endpoints` | [] | Role-based endpoint protection |

---

## 🔒 Security Best Practices

1. **JWT Secret**: Use a strong, randomly generated secret (at least 256 bits)
2. **HTTPS**: Always use HTTPS in production
3. **Password Policy**: Enforce strong passwords (implemented via regex validation)
4. **Token Rotation**: Refresh tokens are rotated on each use
5. **MFA Codes**: Automatically expire after 10 minutes
6. **Code Cleanup**: Expired MFA codes are cleaned up hourly via scheduled task
7. **Transaction Isolation**: MFA code generation uses `REQUIRES_NEW` propagation to ensure codes are saved even if parent transactions roll back

---

## 🎯 Frontend Integration Example

### React/TypeScript Example

```typescript
// Login with MFA handling
const login = async (username: string, password: string) => {
  try {
    const response = await axios.post('/auth/login', { username, password });
    
    if (response.status === 202) {
      // MFA required
      const { userId } = response.data;
      // Redirect to MFA verification page
      navigate(`/verify-mfa?userId=${userId}`);
    } else {
      // Login successful
      const { accessToken, refreshToken } = response.data;
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', refreshToken);
    }
  } catch (error) {
    if (error.response?.status === 403) {
      // Email not verified
      const userId = error.response.data.message.split(':')[1];
      navigate(`/verify-email?userId=${userId}`);
    }
  }
};
```

---

## 🛠️ Troubleshooting

### Common Issues

**1. "User not found" during registration**
- Ensure `@EnableScheduling` is added to your main application class
- Check that email service is properly configured

**2. MFA codes not being saved**
- Verify `@Modifying` and `@Transactional` annotations are present on repository delete methods
- Check database connection

**3. OAuth2 login not working**
- Verify client IDs and secrets are correct
- Ensure redirect URIs match OAuth provider configuration
- Check that the OAuth provider is properly configured in Google/GitHub/Microsoft console

**4. CORS errors**
- Add your frontend URL to `security.cors.allowed-origins`
- Ensure `security.cors.allow-credentials=true` if using cookies

---

## 📝 License

This module is part of a private Spring Boot starter collection.

---

## 🤝 Contributing

For issues or feature requests, please contact the module maintainer.
