# 🛡️ Spring Security setup

A reusable security module for Spring Boot applications.  
It provides an out-of-the-box setup for **JWT-based** and **OAuth2-based** authentication — configurable via properties.  
Only one mode is active at a time, making it simple to switch between custom JWT authentication and OAuth2 login (Google, GitHub, Azure).

---

## 🚀 Features

- ✅ Plug-and-play Spring Boot security setup  
- 🔐 Supports **JWT** and **OAuth2** (Google, GitHub, Azure)  
- ⚙️ Configuration-driven (no hardcoding)  
- 🧩 Ready-to-use CORS, CSRF, and role-based endpoint protection  
- 🪶 Works as a **starter module** or directly inside a **multi-module project**

---

## 🧰 Setup Steps

### 1. Add Dependency

If published as a JAR:
```xml
 <dependency>
  <groupId>com.starter</groupId>
  <artifactId>security</artifactId>
  <version>0.0.1</version>
</dependency>
```

If included locally, ensure your project recognizes the module in your multi-module build.

---

### 2. Configure Your Application

Add the following properties in your parent project’s `application.properties`:

```properties
# --- Security mode ---
security.oauth2.enabled=true
security.jwt.enabled=false

# --- CORS configuration ---
security.cors.enabled=true
security.cors.allowed-origins=http://localhost:3000
security.cors.allowed-methods=*
security.cors.allowed-headers=*
security.cors.exposed-headers=*
security.cors.allow-credentials=true
security.cors.max-age=3600

# --- Public endpoints ---
security.public-endpoints[0]=/auth/register
security.public-endpoints[1]=/auth/login
security.public-endpoints[2]=/auth/refresh2/**
security.public-endpoints[3]=/auth/me

# --- CSRF configuration ---
security.csrf.enabled=true

# --- JWT configuration ---
security.jwt-secret=REPLACE_WITH_STRONG_SECRET
security.jwt-expiration-seconds=120
security.refresh-token-expiration-seconds=86400

# --- Role-based access control ---
security.role-endpoints[0].pattern=/admin/**
security.role-endpoints[0].roles=ADMIN,MANAGER,GITHUB_ADMIN,GOOGLE_ADMIN,AZURE_ADMIN,OAUTH2_USER
security.role-endpoints[1].pattern=/user/**
security.role-endpoints[1].roles=USER,OIDC_USER,GITHUB_USER,GOOGLE_USER,AZURE_USER
security.role-endpoints[2].pattern=/api/**
security.role-endpoints[2].roles=USER,OIDC_USER
```

#### OAuth2 Client Configuration (example)
```properties
# --- GitHub ---
spring.security.oauth2.client.registration.github.client-id=YOUR_GITHUB_CLIENT_ID
spring.security.oauth2.client.registration.github.client-secret=YOUR_GITHUB_CLIENT_SECRET
spring.security.oauth2.client.registration.github.scope=read:user,user:email

# --- Google ---
spring.security.oauth2.client.registration.google.client-id=YOUR_GOOGLE_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=YOUR_GOOGLE_CLIENT_SECRET
spring.security.oauth2.client.registration.google.scope=openid,profile,email
spring.security.oauth2.client.provider.google.issuer-uri=https://accounts.google.com

# --- Azure/Microsoft ---
spring.security.oauth2.client.registration.azure.client-id=YOUR_AZURE_CLIENT_ID
spring.security.oauth2.client.registration.azure.client-secret=YOUR_AZURE_CLIENT_SECRET
spring.security.oauth2.client.registration.azure.scope=openid,profile,email
spring.security.oauth2.client.registration.azure.redirect-uri={baseUrl}/login/oauth2/code/azure
spring.security.oauth2.client.provider.azure.authorization-uri=https://login.microsoftonline.com/common/oauth2/v2.0/authorize
spring.security.oauth2.client.provider.azure.token-uri=https://login.microsoftonline.com/common/oauth2/v2.0/token
spring.security.oauth2.client.provider.azure.user-info-uri=https://graph.microsoft.com/oidc/userinfo
spring.security.oauth2.client.provider.azure.jwk-set-uri=https://login.microsoftonline.com/common/discovery/v2.0/keys
spring.security.oauth2.client.provider.azure.user-name-attribute=sub
add other properties for azure/microsoft based on requirements.
```

---

### 3. Update Your Application Class

If you are using this module **within the same repository**, make sure Spring scans the module packages.

```java
package com.test.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EntityScan("com.starter.security.model")
@EnableJpaRepositories("com.starter.security.repository")
@ComponentScan(basePackages = {
    "com.starter.security",
    "com.starter.security.service",
    "com.starter.security.serviceimpl",
    "com.starter.security.eventlistener"
})
@EnableMethodSecurity
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

---

Once running:
- JWT login endpoints (`/auth/login`, `/auth/register`, `/auth/refresh2/**`) will be active  
- OAuth2 login will redirect to configured providers (Google/GitHub/Azure)

---

## 🔑 Example Usage (JWT Mode)

**Request**
```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

**Response**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
