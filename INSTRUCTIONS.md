# Complete NestJS OAuth 2.0 Identity Provider with Key Management Service

Build a production-ready NestJS OAuth 2.0 Authorization Server featuring enterprise-grade user authentication, PKCE flow support, and automated Key Management Service (KMS) with RSA key rotation. Fully compliant with RFC 7636 (OAuth 2.0 PKCE), RFC 6749 (OAuth 2.0), RFC 7517 (JSON Web Key), and OpenID Connect specifications.

## System Architecture & Core Modules

### Enterprise Module Structure

```typescript
AppModule
├── AuthModule              // User authentication with Argon2id hashing
├── AuthorizationModule     // OAuth 2.0 flows with PKCE support
├── KeyManagementModule     // Enterprise KMS with automated rotation
├── ClientModule           // OAuth client registration & management
├── UserModule             // OpenID Connect compliant user entities
└── ConfigModule           // Environment configuration management
```

### Key Management Service (KMS) - Core Component

**Primary Responsibility**: Centralized cryptographic key lifecycle management

- **KeyGenerationService**: RSA key pair creation using Node.js crypto
- **KeyRotationService**: Automated daily rotation with cron scheduling
- **KeyStorageService**: Secure key persistence with AES encryption at rest
- **CryptographicService**: JWT signing/verification with multi-key support
- **JWKSService**: Public key distribution via JWKS endpoint

## Complete User Authentication System

### Authentication Flow with Argon2id Security

```
User Registration → Argon2id Hashing → Session Creation → MFA Setup (Optional)
                                    ↓
User Login → Credential Validation → MFA Challenge → Session Management
                                    ↓
OAuth Authorization → User Consent → Authorization Code → JWT Token
```

### Authentication Endpoints

```typescript
// Core authentication endpoints
GET  /auth/login                 // Secure login form with CSRF protection
POST /auth/login                 // Credential validation + optional MFA
POST /auth/logout                // Session termination and cleanup
POST /auth/register              // User registration with Argon2id hashing
GET  /auth/forgot-password       // Password recovery form
POST /auth/forgot-password       // Send password reset email
GET  /auth/reset-password/:token // Password reset form with token
POST /auth/reset-password        // Complete password reset
GET  /auth/mfa/setup            // TOTP QR code generation
POST /auth/mfa/verify           // MFA code verification
```

### Enterprise Security Features

- **Argon2id Password Hashing**: Memory-hard function with configurable parameters
- **Session Security**: HTTP-only cookies with secure flags and SameSite protection
- **Brute Force Protection**: Account lockout after 5 failed attempts (15-minute duration)
- **CSRF Protection**: Double-submit cookie pattern on all forms
- **MFA Integration**: TOTP with encrypted backup codes
- **Input Validation**: Comprehensive validation using class-validator
- **Rate Limiting**: Configurable limits on authentication endpoints

## OAuth 2.0 Authorization Server Implementation

### Complete OAuth Flow with PKCE

```
1. Client → /oauth/authorize (response_type=code, PKCE parameters)
2. Authentication Check → Redirect to /auth/login if needed
3. User Authentication → Argon2id validation + optional MFA
4. Return to OAuth Flow → Display consent form
5. User Consent → Scope approval/denial
6. Authorization Code → Generated with PKCE challenge stored
7. Client → /oauth/token (code + code_verifier)
8. PKCE Validation → Code verifier against stored challenge
9. JWT Token → Signed with current KMS active key
```

### OAuth Endpoints

```typescript
// OAuth 2.0 endpoints
GET  /oauth/authorize           // Authorization endpoint with PKCE support
POST /oauth/token               // Token exchange with PKCE validation
GET  /oauth/userinfo            // User information (OpenID Connect)
GET  /.well-known/jwks.json     // Public keys for JWT validation
GET  /.well-known/openid-configuration // Provider metadata
```

### PKCE Implementation (RFC 7636 Compliant)

```typescript
interface PKCEChallenge {
  code_challenge: string;           // Base64URL encoded challenge
  code_challenge_method: 'S256' | 'plain'; // SHA256 or plain text
  code_verifier?: string;           // Only during validation
}

// PKCE validation flow
1. Client generates code_verifier (43-128 characters)
2. Client creates code_challenge = BASE64URL(SHA256(code_verifier))
3. Authorization request includes code_challenge + method
4. Store challenge with authorization code
5. Token request includes code_verifier
6. Validate: BASE64URL(SHA256(code_verifier)) === stored code_challenge
```

## Enterprise Key Management Service (KMS)

### KMS Architecture & Automated Rotation

```typescript
@Module({
  imports: [
    ConfigModule,
    TypeOrmModule.forFeature([CryptographicKey, KeyRotationLog]),
    ScheduleModule.forRoot(), // Enable cron scheduling
  ],
  providers: [
    KeyGenerationService, // RSA key pair generation (Node.js crypto)
    KeyRotationService, // Automated lifecycle management
    KeyStorageService, // Secure persistence + encryption at rest
    CryptographicService, // JWT signing/verification operations
    JWKSService, // Public key distribution
  ],
  controllers: [JWKSController],
  exports: [CryptographicService, JWKSService],
})
export class KeyManagementModule {}
```

### Automated Key Rotation System

```typescript
@Injectable()
export class KeyRotationService {
  @Cron('0 2 * * *') // Daily rotation at 2 AM
  async scheduledKeyRotation(): Promise<void> {
    await this.performKeyRotation('scheduled');
  }

  // Complete key rotation process
  async performKeyRotation(reason: string): Promise<CryptographicKey> {
    // 1. Generate new 2048-bit RSA key pair
    const newKey = await this.keyGenerationService.generateRSAKeyPair();

    // 2. Store new key as active (AES encrypted private key)
    const savedKey = await this.keyStorageService.storeKey(newKey, true);

    // 3. Mark previous keys for overlap period (1 hour default)
    await this.keyStorageService.markKeysForRotation();

    // 4. Log rotation event for audit trail
    await this.logRotationEvent(reason, savedKey.kid);

    // 5. Schedule cleanup of expired keys
    await this.scheduleKeyCleanup();

    return savedKey;
  }

  // Emergency rotation capability
  async emergencyRotation(reason: string): Promise<void> {
    await this.logSecurityEvent('EMERGENCY_KEY_ROTATION', reason);
    await this.performKeyRotation(`emergency: ${reason}`);
  }
}
```

### JWT Operations with Multi-Key Support

```typescript
@Injectable()
export class CryptographicService {
  // JWT signing with current active key
  async signJWT(payload: object): Promise<string> {
    const activeKey = await this.keyStorageService.getActiveSigningKey();
    const privateKey = this.decryptPrivateKey(activeKey.privateKey);

    return jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
      keyid: activeKey.kid,
      expiresIn: '1h',
      issuer: this.configService.get('JWT_ISSUER'),
      audience: this.configService.get('JWT_AUDIENCE'),
    });
  }

  // Multi-key verification for zero-downtime rotation
  async verifyJWT(token: string): Promise<any> {
    const decoded = jwt.decode(token, { complete: true });
    const kid = decoded?.header?.kid;

    // Try specific key first
    if (kid) {
      const key = await this.keyStorageService.getKeyByKid(kid);
      if (key && !this.isKeyExpired(key)) {
        return this.verifyWithKey(token, key.publicKey);
      }
    }

    // Fallback: try all valid keys during rotation overlap
    const validKeys = await this.keyStorageService.getValidVerificationKeys();
    for (const key of validKeys) {
      try {
        return this.verifyWithKey(token, key.publicKey);
      } catch (error) {
        continue; // Try next key
      }
    }

    throw new UnauthorizedException('Invalid token signature');
  }
}
```

## Database Schema (PostgreSQL + TypeORM)

```sql
-- OpenID Connect compliant users
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sub VARCHAR(255) UNIQUE NOT NULL,           -- Subject identifier
  email VARCHAR(255) UNIQUE,
  email_verified BOOLEAN DEFAULT FALSE,
  name VARCHAR(255),
  given_name VARCHAR(255),
  family_name VARCHAR(255),
  picture TEXT,
  password_hash VARCHAR(255),                 -- Argon2id hash
  failed_login_attempts INTEGER DEFAULT 0,
  locked_until TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Secure session management
CREATE TABLE user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id VARCHAR(255) UNIQUE NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id),
  ip_address INET,
  user_agent TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  last_accessed TIMESTAMP DEFAULT NOW()
);

-- OAuth client applications
CREATE TABLE oauth_clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id VARCHAR(255) UNIQUE NOT NULL,
  client_secret_hash VARCHAR(255),            -- Argon2id hash
  client_type VARCHAR(50) DEFAULT 'confidential', -- 'public' or 'confidential'
  redirect_uris TEXT[],
  allowed_scopes TEXT[],
  client_name VARCHAR(255),
  requires_pkce BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW()
);

-- User consent tracking (OpenID Connect)
CREATE TABLE user_consents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  client_id VARCHAR(255) NOT NULL,
  scopes TEXT[],
  granted_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  is_active BOOLEAN DEFAULT TRUE,
  UNIQUE(user_id, client_id)
);

-- KMS: Cryptographic keys with rotation support
CREATE TABLE cryptographic_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kid VARCHAR(255) UNIQUE NOT NULL,           -- Key ID for JWKS
  algorithm VARCHAR(20) DEFAULT 'RS256',
  public_key TEXT NOT NULL,                   -- PEM format
  private_key TEXT NOT NULL,                  -- AES encrypted PEM
  is_active BOOLEAN DEFAULT TRUE,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  rotated_at TIMESTAMP,
  key_usage VARCHAR(50) DEFAULT 'signing',    -- 'signing', 'verification'
  rotation_reason VARCHAR(255)                -- 'scheduled', 'emergency', 'manual'
);

-- KMS: Key rotation audit log
CREATE TABLE key_rotation_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  old_kid VARCHAR(255),
  new_kid VARCHAR(255),
  rotation_type VARCHAR(50),                  -- 'scheduled', 'emergency', 'manual'
  rotation_reason TEXT,
  rotated_at TIMESTAMP DEFAULT NOW(),
  rotated_by VARCHAR(255)                     -- 'system' or user identifier
);

-- Authorization codes with PKCE support
CREATE TABLE authorization_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code VARCHAR(255) UNIQUE NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  user_id UUID NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge VARCHAR(255),                -- PKCE challenge
  code_challenge_method VARCHAR(10),          -- 'S256' or 'plain'
  scope TEXT,
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);

-- MFA secrets (TOTP)
CREATE TABLE mfa_secrets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  secret VARCHAR(255) NOT NULL,               -- AES encrypted TOTP secret
  is_verified BOOLEAN DEFAULT FALSE,
  backup_codes TEXT[],                        -- AES encrypted backup codes
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id)
);
```

## Technical Implementation Stack

### Core Dependencies

```bash
# Framework & Database
npm install @nestjs/common @nestjs/core @nestjs/platform-express
npm install @nestjs/typeorm typeorm pg @nestjs/config

# Authentication & Security (Argon2id recommended)
npm install argon2                           # Superior to bcrypt
npm install @nestjs/passport passport passport-local
npm install express-session connect-redis redis
npm install helmet csurf express-rate-limit @nestjs/throttler

# Key Management Service
npm install @nestjs/jwt jsonwebtoken @types/jsonwebtoken
npm install @nestjs/schedule                 # Cron-based key rotation
# Using built-in Node.js crypto module (no external crypto libs)

# Validation & Utilities
npm install class-validator class-transformer
npm install speakeasy qrcode @types/qrcode   # MFA support
npm install nodemailer @types/nodemailer    # Password reset emails

# Development & Testing
npm install --save-dev @nestjs/testing jest supertest
npm install --save-dev @types/jest @types/supertest
```

### Production Environment Configuration

```env
# Database Configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/oauth_db
DATABASE_SSL=true
DATABASE_POOL_SIZE=20

# Redis Session Store
REDIS_URL=redis://localhost:6379
REDIS_CLUSTER_ENABLED=false

# Authentication Security (Argon2id)
ARGON2_MEMORY_COST=65536                    # 64 MB memory cost
ARGON2_TIME_COST=3                          # 3 iterations
ARGON2_PARALLELISM=1                        # Single thread
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900                        # 15 minutes
SESSION_SECRET=your-session-secret-key
SESSION_TTL=3600                            # 1 hour
REMEMBER_ME_TTL=2592000                     # 30 days

# Key Management Service Configuration
KMS_KEY_SIZE=2048                           # RSA key size
KMS_ROTATION_INTERVAL=86400                 # 24 hours (daily rotation)
KMS_OVERLAP_PERIOD=3600                     # 1 hour validation overlap
KMS_CLEANUP_INTERVAL=7200                   # 2 hours for expired key cleanup
PRIVATE_KEY_ENCRYPTION_SECRET=your-aes-key  # AES key for private key encryption
JWKS_CACHE_TTL=3600                         # JWKS endpoint cache

# JWT Configuration
JWT_ISSUER=https://your-domain.com
JWT_AUDIENCE=your-client-apps
JWT_ALGORITHM=RS256

# OAuth Configuration
AUTHORIZATION_CODE_TTL=600                  # 10 minutes
ACCESS_TOKEN_TTL=3600                       # 1 hour
REFRESH_TOKEN_TTL=86400                     # 24 hours

# MFA Configuration (Optional)
MFA_ISSUER=YourAppName
MFA_BACKUP_CODES_COUNT=10

# Email Configuration (Password Reset)
EMAIL_HOST=smtp.yourdomain.com
EMAIL_PORT=587
EMAIL_USER=noreply@yourdomain.com
EMAIL_PASS=your-email-password
EMAIL_FROM=noreply@yourdomain.com
RESET_TOKEN_TTL=3600                        # 1 hour reset token validity

# Server Configuration
PORT=3000
BASE_URL=https://your-domain.com
NODE_ENV=production

# Security Headers & CORS
CORS_ORIGINS=https://your-client-app.com,https://another-client.com
HELMET_ENABLED=true
RATE_LIMIT_WINDOW=900000                    # 15 minutes
RATE_LIMIT_MAX=100                          # Max requests per window

# Monitoring & Logging
LOG_LEVEL=info
LOG_FORMAT=json
ENABLE_REQUEST_LOGGING=true
METRICS_ENABLED=true
```

## Security Implementation Details

### Argon2id Password Security

```typescript
@Injectable()
export class PasswordService {
  async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id, // Most secure variant
      memoryCost: this.configService.get('ARGON2_MEMORY_COST'),
      timeCost: this.configService.get('ARGON2_TIME_COST'),
      parallelism: this.configService.get('ARGON2_PARALLELISM'),
    });
  }

  async verifyPassword(hash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      this.logger.warn('Password verification failed', { error });
      return false;
    }
  }
}
```

### JWT Token Structure

```json
{
  "header": {
    "typ": "JWT",
    "alg": "RS256",
    "kid": "2024-03-15-001"
  },
  "payload": {
    "sub": "user-uuid-here",
    "aud": "client-id",
    "iss": "https://your-domain.com",
    "iat": 1710504000,
    "exp": 1710507600,
    "scope": "openid profile email",
    "email": "user@example.com",
    "email_verified": true
  }
}
```

### JWKS Endpoint Response

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-03-15-001",
      "alg": "RS256",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-03-14-001",
      "alg": "RS256",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    }
  ]
}
```

## OpenID Connect User Entity Compliance

### User Information Response

```typescript
interface OpenIDUserInfo {
  sub: string; // Subject identifier (required)
  name?: string; // Full name
  given_name?: string; // First name
  family_name?: string; // Last name
  email?: string; // Email address
  email_verified?: boolean; // Email verification status
  picture?: string; // Profile picture URL
  updated_at?: number; // Last profile update timestamp
  // Additional custom claims based on requested scopes
}

// Scope-based data access
// openid: sub only
// profile: name, given_name, family_name, picture, updated_at
// email: email, email_verified
```

## Production Deployment & Monitoring

### Docker Configuration

```dockerfile
# Multi-stage build for production
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine AS production
RUN addgroup -g 1001 -S nodejs && adduser -S nestjs -u 1001
WORKDIR /app
COPY --from=builder --chown=nestjs:nodejs /app/node_modules ./node_modules
COPY --chown=nestjs:nodejs . .
USER nestjs
EXPOSE 3000
CMD ["node", "dist/main"]
```

### Health Checks & Monitoring

```typescript
@Controller('health')
export class HealthController {
  @Get()
  async getHealth(): Promise<HealthStatus> {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      database: await this.checkDatabase(),
      redis: await this.checkRedis(),
      kms: await this.checkKeyManagement(),
    };
  }

  @Get('kms')
  async getKMSStatus(): Promise<KMSHealth> {
    const activeKey = await this.kmsService.getActiveKey();
    const nextRotation = await this.kmsService.getNextRotationTime();

    return {
      activeKeyId: activeKey.kid,
      nextRotation,
      keysInRotation: await this.kmsService.getOverlapKeyCount(),
    };
  }
}
```

### Security Monitoring

```typescript
@Injectable()
export class SecurityMonitoringService {
  // Monitor failed login attempts
  async logFailedLogin(email: string, ip: string): Promise<void> {
    await this.incrementFailedAttempts(email);

    if (await this.isUnusualActivity(email, ip)) {
      await this.alertService.sendSecurityAlert('UNUSUAL_LOGIN_ACTIVITY', {
        email,
        ip,
        timestamp: new Date(),
      });
    }
  }

  // Monitor key rotation events
  async logKeyRotation(event: KeyRotationEvent): Promise<void> {
    this.logger.warn('Key rotation completed', {
      reason: event.reason,
      oldKid: event.oldKid,
      newKid: event.newKid,
      timestamp: event.timestamp,
    });

    if (event.reason.startsWith('emergency')) {
      await this.alertService.sendCriticalAlert('EMERGENCY_KEY_ROTATION', event);
    }
  }
}
```

## Compliance & Standards

### RFC Compliance

- **RFC 7636**: OAuth 2.0 Proof Key for Code Exchange (PKCE) - Complete implementation with S256 and plain methods
- **RFC 6749**: OAuth 2.0 Authorization Framework - Full authorization server with proper error handling
- **RFC 7517**: JSON Web Key (JWK) - JWKS endpoint with automated key rotation
- **RFC 7518**: JSON Web Algorithms (JWA) - RSA-256 algorithm support with Node.js crypto
- **OpenID Connect Core 1.0**: User entity compliance and UserInfo endpoint with scope-based access

### Security Best Practices

- **OWASP Top 10 Protection**: Input validation, authentication, session management, encryption
- **Key Management**: Enterprise-grade KMS with automated rotation and encryption at rest
- **Password Security**: Argon2id memory-hard hashing with configurable parameters
- **Session Security**: HTTP-only cookies, CSRF protection, secure flags
- **Rate Limiting**: Configurable limits on authentication and token endpoints
- **Audit Logging**: Comprehensive security event logging for compliance

## Testing Strategy

### Comprehensive Test Suite

```bash
# Unit Tests
npm run test                    # All unit tests
npm run test:auth              # Authentication module tests
npm run test:oauth             # OAuth flow tests
npm run test:kms               # Key Management Service tests

# Integration Tests
npm run test:integration       # End-to-end OAuth flows
npm run test:security          # Security and penetration tests
npm run test:performance       # Load and performance tests

# Test Coverage
npm run test:coverage          # Generate coverage reports
```

### Test Categories

- **Authentication Tests**: Argon2id hashing, session management, MFA flows
- **OAuth Flow Tests**: Complete authorization flows with different client types
- **PKCE Tests**: S256 and plain challenge method validation
- **KMS Tests**: Key generation, rotation, emergency rotation, cleanup
- **Security Tests**: Brute force protection, CSRF, XSS, injection attacks
- **Performance Tests**: Concurrent users, token validation, database queries
- **Integration Tests**: Complete user journeys from registration to token usage

This comprehensive OAuth 2.0 Identity Provider implementation provides enterprise-grade security, automated key management, and full compliance with modern authentication standards while maintaining high performance and scalability.
