# PMCU Project – DSS API Integration (POC Phase)

This document outlines the full procedure for integrating with Dahua DSS V8.6 APIs during the PMCU Project POC phase.

---

## ✅ Task 1: POC Development Procedure

### 1. Environment & Prep (📖 Section 1.1)
- Deploy a DSS/VMS instance with valid license and at least one connected device.
- Add your client/dev machine IP to the **HTTP Allowlist** via:
  - `System Parameters → Security Configuration → HTTP Allowlist` (📖 Section 2.1.2)
- This is required to call DSS APIs over HTTP (port 80).

---

### 2. Spring Boot Project Setup
- Create a Spring Boot 3.x project with the following dependencies:
  - `spring-boot-starter-web`
  - `spring-boot-starter-amqp` (for ActiveMQ MQ integration)
  - HTTP client: either `RestTemplate` or `WebClient`

---

### 3. Implement Auth Flow

#### 🔐 First Login (📖 Section 3.1.1)
- Endpoint: `POST /brms/api/v1.0/accounts/authorize`
- Request payload:
  ```json
  {
    "userName": "system",
    "ipAddress": "192.168.x.x",
    "clientType": "WINPC_V2"
  }
  ```
- Parse response:
  - `realm`
  - `randomKey`
  - `encryptType` (usually `"MD5"`)
  - `publicKey` (only for RSA)

#### 🔐 Second Login (📖 Section 3.1.2)
- Reuse the same endpoint, send payload with:
  - `signature` (MD5 hash: `md5(md5(user:realm:pass) + ":" + randomKey)`)
  - `mac`, `encryptType`, `randomKey`, `clientType`, `ipAddress`, `secretKey`, `secretVector`
- Parse second response (from **headers**, not body):
  - `X-Subject-Token` → used for all subsequent API calls
- JSON response contains:
  - `userId`, `userGroupId`, `credential`, `verification`

---

### 4. Session Maintenance (📖 Section 3.1.3, 3.1.4)
- Call:
  - `PUT /brms/api/v1.0/accounts/keepalive` before token expiration
  - Optionally: `PUT /brms/api/v1.0/accounts/updateToken` to renew token
- Both requests **require `X-Subject-Token` header**

---

### 5. Get MQ Config (📖 Section 3.2.1)
- Endpoint: `GET /brms/api/v1.0/BRM/Config/GetMqConfig`
- Use `X-Subject-Token` header
- Parse response:
  - `host`, `port`, `accessKey`, `encryptedPassword`, `subscribeTopics`
- Decrypt `encryptedPassword` using AES-CBC with `secretKey` and `secretVector` from second login

---

### 6. Subscribe & Handle MQ Messages (📖 Section 2.2)
- Use Spring AMQP or JMS to connect to ActiveMQ
- Topics:
  - `mq.alarm.msg.topic.{userId}`
  - `mq.alarm.msg.group.topic.{userGroupId}`
- Parse messages based on fields:
  - `eventType`, `snapUrl`, `timestamp`, `deviceId`, etc.

---

### 7. Visitor Whitelist Integration (📖 Section 3.9)
- Call:
  - `POST /brms/api/v1.0/visitor/add`
- Use visitor info received in alarm/trigger events

---

### 8. Demo & Documentation
- Export all steps to Postman or HTTPie collection:
  - First login → second login → keepalive → getMqConfig → MQ subscribe → visitor-add
- Prepare:
  - A detailed README
  - Updated sequence diagrams
  - Swagger/OpenAPI for your internal wrapper endpoints

---

## ✅ Task 2: API Testing Preparation

### 1. Whitelist Client IP (📖 Section 2.1.2)
- DSS UI → `System Parameters > Security Configuration > HTTP Allowlist`
- Add your dev machine's IP address

### 2. Open Required Network Ports
Ensure the following ports are open (on DSS firewall, server security group, etc.):

| Port | Purpose             |
|------|---------------------|
| 80   | HTTP API access     |
| 443  | HTTPS API access    |
| 8080 | Spring Boot backend |
| 61613 / 61616 | ActiveMQ (MQ config) |

### 3. HTTP Headers for All API Calls
```http
Accept-Language: en
Content-Type: application/json;charset=UTF-8
X-Subject-Token: <token-from-second-login-header>
```

### 4. Verify Network Connectivity
Run these from your client machine:
```sh
ping 192.168.1.1
telnet 192.168.1.1 80
telnet 192.168.1.1 443
```

### 5. Handle Self-signed SSL (if using HTTPS)
- If DSS uses self-signed certs:
  - Disable SSL verification in Postman or
  - Import cert into JVM truststore

### 6. Logging
- Log all HTTP requests/responses at `DEBUG` level
- **Mask sensitive data** like:
  - `signature`, `secretKey`, `password`, `secretVector`

---

## ✅ Task 3: Integration & Testing

### 1. Unit Tests
- Mock HTTP client for:
  - `/authorize`
  - `/getMqConfig`

### 2. Integration Tests
- Use:
  - `TestContainers` for embedded ActiveMQ
  - Stub DSS endpoints
  - Simulate sample MQ messages

### 3. End-to-End Smoke Test
- Flow:
  - Login → Keepalive → GetMqConfig → MQ Subscribe → Add Visitor

---

## ✅ Task 4: Error Handling & Recovery

- Handle common DSS error codes (📖 Section 6.2):
  - 401 / 403: session expired → re-login
  - 5xx: retry with backoff
- Handle malformed MQ messages
- Auto-reconnect to ActiveMQ on loss

---

## ✅ Task 5: Security Considerations

- Never log or expose:
  - `password`, `signature`, `secretKey`, `secretVector`, `token`
- Enforce HTTPS for all environments
- Use Spring Vault or AWS Secrets Manager for credential storage
- Validate SSL certificates

---

## ✅ Task 6: Observability

- Add Spring Boot Actuator endpoints:
  - `/actuator/health` → show MQ status, DSS session alive
- Add custom health indicator for:
  - Token validity
  - MQ listener status

---
