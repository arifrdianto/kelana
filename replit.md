# Kelana - NestJS OAuth 2.0 Identity Provider

## Overview

Kelana is a production-ready NestJS OAuth 2.0 Authorization Server featuring enterprise-grade user authentication, PKCE flow support, and automated Key Management Service (KMS) with RSA key rotation. The application is designed as a comprehensive identity provider with OpenID Connect compliance and centralized cryptographic key lifecycle management.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Core Module Structure
The application follows a modular NestJS architecture with clear separation of concerns:

- **AppModule**: Main application module with conditional database and KMS loading
- **KmsModule**: Enterprise-grade Key Management Service for cryptographic operations
- **CacheModule**: Redis-based caching layer using Keyv and Cacheable
- **ConfigModule**: Global environment configuration management

### Key Management Service (KMS)
The KMS is the cornerstone component providing centralized cryptographic key lifecycle management:

- **KeyGenerationService**: RSA key pair creation using Node.js crypto primitives
- **KeyRotationService**: Automated daily rotation with cron scheduling (3 AM daily)
- **KeyStorageService**: Secure key persistence with AES-256-CTR encryption at rest
- **CryptographicService**: JWT signing/verification with multi-key support
- **JwksService**: RFC 7517 compliant public key distribution via JWKS endpoint
- **KeyValidationService**: JWK compliance validation and key integrity checks

### Database Architecture
Uses TypeORM with PostgreSQL for data persistence:

- **BaseEntity**: Common entity structure with UUID primary keys, timestamps, soft delete, and optimistic locking
- **CryptographicKey Entity**: Stores encrypted RSA key pairs with metadata (kid, algorithm, expiration, usage)
- **KeyRotationLog Entity**: Audit trail for all key rotation events with detailed logging
- **Migration Support**: Database schema versioning with TypeORM migrations

### Security Design Patterns
- **Encryption at Rest**: AES-256-CTR encryption for private keys using scrypt-derived keys
- **Key Rotation**: Automated 30-day key lifecycle with 7-day pre-rotation window
- **CSRF Protection**: Built-in protection for authentication endpoints
- **Rate Limiting**: Configurable throttling with Redis backend
- **Helmet Security**: Comprehensive security headers with CSP configuration

### Caching Strategy
Redis-based multi-layer caching architecture:
- **Primary Cache**: In-memory for hot data
- **Secondary Cache**: Redis persistence using Keyv store
- **Error Handling**: Graceful degradation on cache failures
- **TTL Management**: Configurable time-to-live settings

### API Design
- **Versioned APIs**: URI-based versioning (v1) with default fallback
- **OpenAPI Documentation**: Swagger integration with JWT bearer auth
- **CORS Configuration**: Environment-based origin control
- **RESTful Endpoints**: Standard HTTP methods with proper status codes

### Monitoring and Observability
- **Structured Logging**: Pino logger with request correlation IDs
- **Health Checks**: Terminus-based health monitoring
- **Error Handling**: Custom exception hierarchy for KMS operations
- **Audit Trails**: Comprehensive logging for all key management operations

## External Dependencies

### Database
- **PostgreSQL**: Primary data store for entities and key storage
- **TypeORM**: ORM with migration support and connection pooling

### Caching and Session Management
- **Redis**: Distributed caching and session storage
- **Keyv**: Universal key-value storage interface
- **Cacheable**: Multi-layer caching with TTL management

### Security and Authentication
- **jsonwebtoken**: JWT creation, signing, and verification
- **helmet**: Security middleware for HTTP headers
- **@nestjs/passport**: Authentication strategies integration
- **@nestjs/throttler**: Rate limiting and DDoS protection

### Scheduling and Background Jobs
- **@nestjs/schedule**: Cron-based task scheduling
- **cron**: Advanced cron expression parsing

### Monitoring and Documentation
- **@nestjs/swagger**: OpenAPI documentation generation
- **@nestjs/terminus**: Application health checks
- **nestjs-pino**: High-performance logging
- **pino-pretty**: Development-friendly log formatting

### Development and Build Tools
- **@nestjs/cli**: NestJS command-line interface
- **TypeScript**: Type-safe development with modern ES features
- **ESLint**: Code quality and style enforcement
- **class-validator**: DTO validation with decorators
- **class-transformer**: Object transformation and serialization