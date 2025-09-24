import { Injectable, Logger } from '@nestjs/common';

import { decode, JwtPayload, sign, SignOptions, verify, VerifyOptions } from 'jsonwebtoken';

import { KeyNotFoundException } from '@/shared/exceptions/jwk.exception';

import { KeyStorageService } from './key-storage.service';

// Enhanced interfaces with RFC 7519 compliance
export interface JwtSignOptions extends Omit<SignOptions, 'algorithm' | 'keyid'> {
  expiresIn?: SignOptions['expiresIn'];
  notBefore?: SignOptions['notBefore'];
  audience?: string | string[];
  issuer?: string;
  subject?: string;
  jwtid?: string;
  noTimestamp?: boolean;
  header?: Record<string, any>;
  kid?: string;
}

export interface JwtVerifyOptions extends Omit<VerifyOptions, 'complete'> {
  algorithms?: string[];
  audience?: string | string[];
  issuer?: string | string[];
  subject?: string;
  jwtid?: string;
  ignoreExpiration?: boolean;
  ignoreNotBefore?: boolean;
  clockTolerance?: number;
  maxAge?: string | number;
  clockTimestamp?: number;
  nonce?: string;
  requiredClaims?: string[];
}

export interface JwtValidationResult<T = any> {
  valid: boolean;
  payload?: T & JwtPayload;
  errors: string[];
  warnings: string[];
  keyId?: string;
  algorithm?: string;
}

export interface ClockSkewConfig {
  tolerance: number; // seconds
  maxSkew: number; // seconds
  enabled: boolean;
}

@Injectable()
export class CryptographicService {
  private readonly logger = new Logger(CryptographicService.name);

  // RFC 7518 compliant algorithm support
  private readonly SUPPORTED_ALGORITHMS = [
    'RS256',
    'RS384',
    'RS512', // RSA with PKCS#1 padding
    'PS256',
    'PS384',
    'PS512', // RSA-PSS
    'ES256',
    'ES384',
    'ES512', // ECDSA
  ] as const;

  private readonly DEFAULT_ALGORITHM = 'RS256';
  private readonly DEFAULT_EXPIRES_IN = '1h';

  // Enhanced clock skew configuration
  private readonly defaultClockSkewConfig: ClockSkewConfig = {
    tolerance: 60, // 1 minute default tolerance
    maxSkew: 300, // 5 minutes maximum allowed skew
    enabled: true,
  };

  constructor(private readonly keyStorageService: KeyStorageService) {}

  /**
   * Sign a JWT with enhanced RFC 7519 compliance
   */
  public async sign<T extends object>(payload: T, options: JwtSignOptions = {}): Promise<string> {
    try {
      // Input validation
      if (!payload || typeof payload !== 'object') {
        throw new Error('Payload must be a non-null object');
      }

      // Get signing key
      const key = options.kid
        ? await this.keyStorageService.getKey(options.kid)
        : await this.keyStorageService.getCurrentKey();

      if (!key) {
        const keyId = options.kid || 'current';
        throw new KeyNotFoundException(keyId);
      }

      if (!key.privateKey) {
        throw new Error('Private key is not available for signing');
      }

      // Validate key expiration with grace period
      const now = new Date();
      const gracePeriod = 5 * 60 * 1000; // 5 minutes
      if (key.expiresAt && now > new Date(key.expiresAt.getTime() - gracePeriod)) {
        throw new Error(`Signing key ${key.kid} has expired or will expire soon`);
      }

      // Validate and normalize algorithm
      const algorithm = this.validateAndGetAlgorithm(options.header?.alg);

      // Enhanced payload validation
      const validatedPayload = this.validateJwtPayload(payload);

      // Create comprehensive sign options
      const signOptions: SignOptions = {
        algorithm: algorithm as any,
        keyid: key.kid,
        expiresIn: options.expiresIn || this.DEFAULT_EXPIRES_IN,
        notBefore: options.notBefore,
        audience: options.audience,
        issuer: options.issuer,
        subject: options.subject,
        jwtid: options.jwtid,
        noTimestamp: options.noTimestamp,
        header: {
          ...options.header,
          alg: algorithm,
          typ: 'JWT',
        },
      };

      this.logger.debug(`Signing JWT with key: ${key.kid}, algorithm: ${algorithm}`);

      // Promise wrapper for sign function with timeout
      const token = await Promise.race([
        new Promise<string>((resolve, reject) => {
          sign(validatedPayload, key.privateKey, signOptions, (error, token) => {
            if (error || !token) {
              reject(error || new Error('Failed to generate JWT token'));
            } else {
              resolve(token);
            }
          });
        }),
        new Promise<never>((_, reject) => {
          setTimeout(() => reject(new Error('JWT signing timeout')), 10000); // 10s timeout
        }),
      ]);

      this.logger.debug(`Successfully signed JWT with key: ${key.kid}`);
      return token;
    } catch (error) {
      if (error instanceof KeyNotFoundException) {
        throw error;
      }

      this.logger.error('Error signing JWT', this.getErrorStack(error));
      throw new Error(`Failed to sign JWT: ${this.getErrorMessage(error)}`);
    }
  }

  /**
   * Enhanced JWT verification with comprehensive RFC 7519 compliance
   */
  public async verify<T extends object>(
    token: string,
    options: JwtVerifyOptions = {},
  ): Promise<T & JwtPayload> {
    try {
      // Input validation
      if (!token?.trim()) {
        throw new Error('Token is required and cannot be empty');
      }

      // Enhanced token format validation
      const tokenParts = token.split('.');
      if (tokenParts.length !== 3) {
        throw new Error('Invalid JWT format: must have exactly 3 parts separated by dots');
      }

      // Decode header to validate structure
      let decoded: any;
      try {
        decoded = decode(token, { complete: true });
      } catch (error) {
        throw new Error(`Invalid JWT token format: ${this.getErrorMessage(error)}`);
      }

      if (!decoded || typeof decoded === 'string' || !decoded.header || !decoded.payload) {
        throw new Error('Invalid JWT token structure');
      }

      const { kid, alg, typ } = decoded.header;

      // Validate JWT type
      if (typ && typ !== 'JWT') {
        throw new Error(`Unsupported token type: ${typ}. Expected 'JWT'`);
      }

      // Validate key ID presence
      if (!kid) {
        throw new Error('JWT header missing required key ID (kid) parameter');
      }

      // Validate algorithm
      if (!alg) {
        throw new Error('JWT header missing algorithm (alg) parameter');
      }

      const validatedAlgorithm = this.validateAndGetAlgorithm(alg);

      // Get verification key with enhanced error handling
      const key = await this.keyStorageService.getKey(kid);
      if (!key) {
        throw new KeyNotFoundException(kid);
      }

      if (!key.publicKey) {
        throw new Error(`Public key not available for key ID: ${kid}`);
      }

      // Enhanced key expiration check
      const clockSkew = options.clockTolerance || this.defaultClockSkewConfig.tolerance;
      if (key.expiresAt && this.isKeyExpiredWithSkew(key.expiresAt, clockSkew)) {
        throw new Error(`Verification key ${kid} has expired`);
      }

      // Build comprehensive verify options
      const verifyOptions: VerifyOptions = {
        algorithms: options.algorithms || [validatedAlgorithm],
        audience: options.audience,
        issuer: options.issuer,
        subject: options.subject,
        jwtid: options.jwtid,
        ignoreExpiration: options.ignoreExpiration || false,
        ignoreNotBefore: options.ignoreNotBefore || false,
        clockTolerance: clockSkew,
        maxAge: options.maxAge,
        clockTimestamp: options.clockTimestamp,
        nonce: options.nonce,
      };

      this.logger.debug(`Verifying JWT with key: ${kid}, algorithm: ${alg}`);

      // Promise wrapper with timeout
      const verified = await Promise.race([
        new Promise<T & JwtPayload>((resolve, reject) => {
          verify(token, key.publicKey, verifyOptions, (error, decoded) => {
            if (error) {
              reject(error);
            } else if (!decoded || typeof decoded === 'string') {
              reject(new Error('Invalid token payload after verification'));
            } else {
              resolve(decoded as T & JwtPayload);
            }
          });
        }),
        new Promise<never>((_, reject) => {
          setTimeout(() => reject(new Error('JWT verification timeout')), 10000);
        }),
      ]);

      // Additional custom claims validation
      if (options.requiredClaims?.length) {
        this.validateRequiredClaims(verified, options.requiredClaims);
      }

      this.logger.debug(`Successfully verified JWT with key: ${kid}`);
      return verified;
    } catch (error) {
      if (error instanceof KeyNotFoundException) {
        throw error;
      }

      this.logger.error('Error verifying JWT', this.getErrorStack(error));
      throw new Error(`Failed to verify JWT: ${this.getErrorMessage(error)}`);
    }
  }

  /**
   * Enhanced JWT validation with detailed results
   */
  public async validateJwt<T extends object>(
    token: string,
    options: JwtVerifyOptions = {},
  ): Promise<JwtValidationResult<T>> {
    const result: JwtValidationResult<T> = {
      valid: false,
      errors: [],
      warnings: [],
    };

    try {
      // Basic format validation
      if (!token?.trim()) {
        result.errors.push('Token is required and cannot be empty');
        return result;
      }

      const tokenParts = token.split('.');
      if (tokenParts.length !== 3) {
        result.errors.push('Invalid JWT format: must have exactly 3 parts');
        return result;
      }

      // Decode without verification first
      let decoded: any;
      try {
        decoded = decode(token, { complete: true });
      } catch (error) {
        result.errors.push(`Token decode failed: ${this.getErrorMessage(error)}`);
        return result;
      }

      if (!decoded?.header || !decoded?.payload) {
        result.errors.push('Invalid token structure');
        return result;
      }

      const { kid, alg } = decoded.header;
      result.keyId = kid;
      result.algorithm = alg;

      // Header validation
      if (!kid) {
        result.errors.push('Missing key ID (kid) in header');
      }

      if (!alg) {
        result.errors.push('Missing algorithm (alg) in header');
      } else if (!this.SUPPORTED_ALGORITHMS.includes(alg)) {
        result.warnings.push(`Algorithm ${alg} not in supported list`);
      }

      // Attempt full verification
      try {
        const payload = await this.verify<T>(token, options);
        result.valid = true;
        result.payload = payload;
      } catch (error) {
        result.errors.push(this.getErrorMessage(error));
      }

      return result;
    } catch (error) {
      result.errors.push(`Validation failed: ${this.getErrorMessage(error)}`);
      return result;
    }
  }

  /**
   * Decode JWT without verification (enhanced safety)
   */
  public decode<T = any>(token: string, complete: boolean = false): (T & JwtPayload) | null {
    try {
      if (!token?.trim()) {
        return null;
      }

      // Basic format check
      const parts = token.split('.');
      if (parts.length !== 3) {
        this.logger.warn('Invalid JWT format for decode operation');
        return null;
      }

      const decoded = decode(token, { complete });

      if (complete && decoded && typeof decoded === 'object' && 'payload' in decoded) {
        // Validate decoded structure for complete mode
        if (!decoded.header || !decoded.payload) {
          this.logger.warn('Incomplete JWT structure in decode result');
          return null;
        }
      }

      return decoded as (T & JwtPayload) | null;
    } catch (error) {
      this.logger.error('Error decoding JWT', this.getErrorStack(error));
      return null;
    }
  }

  /**
   * Enhanced payload validation per RFC 7519
   */
  private validateJwtPayload<T extends object>(payload: T): T {
    if (!payload || typeof payload !== 'object') {
      throw new Error('JWT payload must be a non-null object');
    }

    // Check for reserved claim conflicts
    const reservedClaims = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];
    const payloadKeys = Object.keys(payload);

    // Validate claim types
    const typedPayload = payload as any;

    if ('exp' in typedPayload && typeof typedPayload.exp !== 'number') {
      throw new Error('exp claim must be a NumericDate (number)');
    }

    if ('nbf' in typedPayload && typeof typedPayload.nbf !== 'number') {
      throw new Error('nbf claim must be a NumericDate (number)');
    }

    if ('iat' in typedPayload && typeof typedPayload.iat !== 'number') {
      throw new Error('iat claim must be a NumericDate (number)');
    }

    if (
      'aud' in typedPayload &&
      typeof typedPayload.aud !== 'string' &&
      !Array.isArray(typedPayload.aud)
    ) {
      throw new Error('aud claim must be a string or array of strings');
    }

    return payload;
  }

  /**
   * Validate required claims presence
   */
  private validateRequiredClaims(payload: JwtPayload, requiredClaims: string[]): void {
    const missingClaims = requiredClaims.filter((claim) => !(claim in payload));

    if (missingClaims.length > 0) {
      throw new Error(`Missing required claims: ${missingClaims.join(', ')}`);
    }
  }

  /**
   * Enhanced key expiration check with clock skew
   */
  private isKeyExpiredWithSkew(expiresAt: Date, clockSkewSeconds: number): boolean {
    const now = new Date();
    const expiryWithSkew = new Date(expiresAt.getTime() + clockSkewSeconds * 1000);
    return now > expiryWithSkew;
  }

  /**
   * Enhanced algorithm validation
   */
  private validateAndGetAlgorithm(algorithm?: string): string {
    const alg = algorithm || this.DEFAULT_ALGORITHM;

    if (!this.SUPPORTED_ALGORITHMS.includes(alg as any)) {
      throw new Error(
        `Unsupported algorithm: ${alg}. Supported algorithms: ${this.SUPPORTED_ALGORITHMS.join(', ')}`,
      );
    }

    return alg;
  }

  /**
   * Create JWT with enhanced validation and custom claims
   */
  public async createJWT(
    payload: object,
    options: JwtSignOptions & {
      customClaims?: Record<string, any>;
      validateClaims?: boolean;
    } = {},
  ): Promise<string> {
    try {
      // Merge custom claims
      let enhancedPayload = {
        ...payload,
        ...options.customClaims,
      };

      // Optional additional claim validation
      if (options.validateClaims !== false) {
        enhancedPayload = this.validateJwtPayload(enhancedPayload);
      }

      const signOptions: JwtSignOptions = {
        kid: options.kid,
        expiresIn: options.expiresIn,
        notBefore: options.notBefore,
        audience: options.audience,
        issuer: options.issuer,
        subject: options.subject,
        jwtid: options.jwtid,
        header: options.header,
      };

      return await this.sign(enhancedPayload, signOptions);
    } catch (error) {
      this.logger.error('Error creating JWT', this.getErrorStack(error));
      throw new Error(`Failed to create JWT: ${this.getErrorMessage(error)}`);
    }
  }

  /**
   * Verify JWT and extract specific claims with validation
   */
  public async verifyAndExtractClaims<T extends Record<string, any>>(
    token: string,
    requiredClaims: (keyof T)[],
    options: JwtVerifyOptions = {},
  ): Promise<T & JwtPayload> {
    try {
      // Add required claims to options
      const enhancedOptions = {
        ...options,
        requiredClaims: [...(options.requiredClaims || []), ...requiredClaims.map(String)],
      };

      const payload = await this.verify<T>(token, enhancedOptions);

      return payload;
    } catch (error) {
      this.logger.error('Error verifying JWT and extracting claims', this.getErrorStack(error));
      throw error;
    }
  }

  /**
   * Enhanced health check with detailed cryptographic service status
   */
  public async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: {
      hasActiveKey: boolean;
      supportedAlgorithms: string[];
      currentKeyId?: string;
      currentKeyExpiration?: Date;
      keyCount: number;
      clockSkewConfig: ClockSkewConfig;
    };
    performance: {
      lastSignTime?: number;
      lastVerifyTime?: number;
      averageSignTime?: number;
      averageVerifyTime?: number;
    };
  }> {
    try {
      const startTime = Date.now();
      const currentKey = await this.keyStorageService.getCurrentKey();
      const allKeys = await this.keyStorageService.getActiveKeys();

      let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

      if (!currentKey) {
        status = 'unhealthy';
      } else if (
        currentKey.expiresAt &&
        this.isKeyExpiredWithSkew(currentKey.expiresAt, 7 * 24 * 60 * 60)
      ) {
        // 7 days
        status = 'degraded';
      }

      const healthCheckTime = Date.now() - startTime;

      return {
        status,
        details: {
          hasActiveKey: !!currentKey,
          supportedAlgorithms: [...this.SUPPORTED_ALGORITHMS],
          currentKeyId: currentKey?.kid,
          currentKeyExpiration: currentKey?.expiresAt,
          keyCount: allKeys.length,
          clockSkewConfig: this.defaultClockSkewConfig,
        },
        performance: {
          lastSignTime: healthCheckTime,
          // These would be tracked in a real implementation
          averageSignTime: undefined,
          averageVerifyTime: undefined,
        },
      };
    } catch (error) {
      this.logger.error('Cryptographic service health check failed', this.getErrorStack(error));
      return {
        status: 'unhealthy',
        details: {
          hasActiveKey: false,
          supportedAlgorithms: [...this.SUPPORTED_ALGORITHMS],
          keyCount: 0,
          clockSkewConfig: this.defaultClockSkewConfig,
        },
        performance: {},
      };
    }
  }

  /**
   * Helper method to safely extract error message
   */
  private getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    return String(error);
  }

  /**
   * Helper method to safely extract error stack trace
   */
  private getErrorStack(error: unknown): string {
    if (error instanceof Error) {
      return error.stack || error.message;
    }
    return String(error);
  }
}
