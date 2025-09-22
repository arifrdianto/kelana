import { Injectable, Logger } from '@nestjs/common';

import { decode, JwtPayload, sign, SignOptions, verify, VerifyOptions } from 'jsonwebtoken';

import { KeyNotFoundException } from '@/shared/exceptions/jwk.exception';

import { KeyStorageService } from './key-storage.service';
import { KeyValidationService } from './key-validation.service';

export interface JwtSignOptions extends Omit<SignOptions, 'algorithm' | 'keyid'> {
  expiresIn?: SignOptions['expiresIn'];
  notBefore?: SignOptions['notBefore'];
  audience?: SignOptions['audience'];
  issuer?: SignOptions['issuer'];
  subject?: SignOptions['subject'];
  noTimestamp?: SignOptions['noTimestamp'];
  header?: SignOptions['header'];
  kid?: string; // Allow override of key ID
}

export interface JwtVerifyOptions extends Omit<VerifyOptions, 'complete'> {
  ignoreExpiration?: boolean;
  ignoreNotBefore?: boolean;
  clockTolerance?: number;
}

@Injectable()
export class CryptographicService {
  private readonly logger = new Logger(CryptographicService.name);
  private readonly DEFAULT_ALGORITHM = 'RS256';
  private readonly DEFAULT_EXPIRES_IN = '1h';
  private readonly SUPPORTED_ALGORITHMS = ['RS256', 'RS384', 'RS512'];

  constructor(
    private readonly keyStorageService: KeyStorageService,
    private readonly keyValidationService: KeyValidationService,
  ) {}

  /**
   * Sign a JWT payload with the current active key or specified key
   */
  public async sign<T extends object>(payload: T, options: JwtSignOptions = {}): Promise<string> {
    try {
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

      // Validate key is not expired
      if (key.expiresAt && new Date() > key.expiresAt) {
        throw new Error(`Signing key ${key.kid} has expired`);
      }

      // Validate algorithm compatibility
      const algorithm = this.validateAndGetAlgorithm(options.header?.alg);

      // Create sign options with proper typing
      const signOptions: SignOptions = {
        algorithm: algorithm as 'RS256',
        keyid: key.kid,
        expiresIn: options.expiresIn || this.DEFAULT_EXPIRES_IN,
        ...options,
      };

      // Remove our custom options that aren't part of SignOptions
      delete (signOptions as any).kid;

      this.logger.debug(`Signing JWT with key: ${key.kid}, algorithm: ${algorithm}`);

      // Use Promise wrapper for sign function
      const token = await new Promise<string>((resolve, reject) => {
        sign(payload, key.privateKey, signOptions, (error, token) => {
          if (error || !token) {
            reject(error || new Error('Failed to generate JWT token'));
          } else {
            resolve(token);
          }
        });
      });

      this.logger.debug(`Successfully signed JWT with key: ${key.kid}`);
      return token;
    } catch (error) {
      if (error instanceof KeyNotFoundException) {
        throw error;
      }

      this.logger.error('Error signing JWT', error.stack);
      throw new Error(`Failed to sign JWT: ${error.message}`);
    }
  }

  /**
   * Verify a JWT token and return the decoded payload
   */
  public async verify<T extends object>(
    token: string,
    options: JwtVerifyOptions = {},
  ): Promise<T & JwtPayload> {
    try {
      if (!token) {
        throw new Error('Token is required');
      }

      // Decode without verification to get the key ID
      const decoded = decode(token, { complete: true });

      if (!decoded || typeof decoded === 'string' || !decoded.header) {
        throw new Error('Invalid JWT token format');
      }

      const { kid, alg } = decoded.header;
      if (!kid) {
        throw new Error('JWT does not contain a key ID (kid) in header');
      }

      // Validate algorithm
      if (alg) {
        this.validateAndGetAlgorithm(alg);
      }

      // Get the verification key
      const key = await this.keyStorageService.getKey(kid);
      if (!key) {
        throw new KeyNotFoundException(kid);
      }

      if (!key.publicKey) {
        throw new Error(`Public key not available for key ID: ${kid}`);
      }

      // Check if key is expired (allow small grace period for clock skew)
      const gracePeriod = 5 * 60 * 1000; // 5 minutes
      if (key.expiresAt && new Date().getTime() > key.expiresAt.getTime() + gracePeriod) {
        throw new Error(`Verification key ${kid} has expired`);
      }

      const verifyOptions: VerifyOptions = {
        algorithms: options.algorithms || [this.DEFAULT_ALGORITHM],
        clockTolerance: options.clockTolerance || 60, // 60 seconds default
        ...options,
      };

      this.logger.debug(
        `Verifying JWT with key: ${kid}, algorithm: ${alg || this.DEFAULT_ALGORITHM}`,
      );

      // Use Promise wrapper for verify function
      const verified = await new Promise<T & JwtPayload>((resolve, reject) => {
        verify(token, key.publicKey, verifyOptions, (error, decoded) => {
          if (error) {
            reject(error);
          } else if (!decoded || typeof decoded === 'string') {
            reject(new Error('Invalid token payload after verification'));
          } else {
            resolve(decoded as T & JwtPayload);
          }
        });
      });

      this.logger.debug(`Successfully verified JWT with key: ${kid}`);
      return verified;
    } catch (error) {
      if (error instanceof KeyNotFoundException) {
        throw error;
      }

      this.logger.error('Error verifying JWT', error.stack);
      throw new Error(`Failed to verify JWT: ${error.message}`);
    }
  }

  /**
   * Decode a JWT token without verification (use with caution)
   */
  public decode<T = any>(token: string, complete: boolean = false): (T & JwtPayload) | null {
    try {
      if (!token) {
        return null;
      }

      const decoded = decode(token, { complete });
      return decoded as (T & JwtPayload) | null;
    } catch (error) {
      this.logger.error('Error decoding JWT', error.stack);
      return null;
    }
  }

  /**
   * Get the public key for a specific key ID
   */
  public async getPublicKey(kid: string): Promise<string> {
    try {
      if (!kid) {
        throw new Error('Key ID is required');
      }

      const key = await this.keyStorageService.getKey(kid);
      if (!key) {
        throw new KeyNotFoundException(kid);
      }

      return key.publicKey;
    } catch (error) {
      if (error instanceof KeyNotFoundException) {
        throw error;
      }

      this.logger.error(`Error getting public key for kid: ${kid}`, error.stack);
      throw new Error(`Failed to get public key: ${error.message}`);
    }
  }

  /**
   * Get the current active public key
   */
  public async getCurrentPublicKey(): Promise<{ kid: string; publicKey: string }> {
    try {
      const key = await this.keyStorageService.getCurrentKey();
      if (!key) {
        throw new KeyNotFoundException('current');
      }

      return {
        kid: key.kid,
        publicKey: key.publicKey,
      };
    } catch (error) {
      if (error instanceof KeyNotFoundException) {
        throw error;
      }

      this.logger.error('Error getting current public key', error.stack);
      throw new Error(`Failed to get current public key: ${error.message}`);
    }
  }

  /**
   * Validate and normalize algorithm
   */
  private validateAndGetAlgorithm(algorithm?: string): string {
    const alg = algorithm || this.DEFAULT_ALGORITHM;

    if (!this.SUPPORTED_ALGORITHMS.includes(alg)) {
      throw new Error(
        `Unsupported algorithm: ${alg}. Supported: ${this.SUPPORTED_ALGORITHMS.join(', ')}`,
      );
    }

    return alg;
  }

  /**
   * Create a JWT with custom claims and validation
   */
  public async createJWT(
    payload: object,
    options: JwtSignOptions & {
      customClaims?: Record<string, any>;
    } = {},
  ): Promise<string> {
    try {
      // Merge custom claims
      const enhancedPayload = {
        ...payload,
        ...options.customClaims,
      };

      // Create signing options
      const signOptions: JwtSignOptions = {
        kid: options.kid,
        expiresIn: options.expiresIn,
        audience: options.audience,
        issuer: options.issuer,
        subject: options.subject,
      };

      return await this.sign(enhancedPayload, signOptions);
    } catch (error) {
      this.logger.error('Error creating JWT', error.stack);
      throw new Error(`Failed to create JWT: ${error.message}`);
    }
  }

  /**
   * Verify JWT and extract specific claims
   */
  public async verifyAndExtractClaims<T extends Record<string, any>>(
    token: string,
    requiredClaims: (keyof T)[],
    options: JwtVerifyOptions = {},
  ): Promise<T & JwtPayload> {
    try {
      const payload = await this.verify<T>(token, options);

      // Check for required claims
      const missingClaims = requiredClaims.filter((claim) => !(claim in payload));
      if (missingClaims.length > 0) {
        throw new Error(`Missing required claims: ${missingClaims.join(', ')}`);
      }

      return payload;
    } catch (error) {
      this.logger.error('Error verifying JWT and extracting claims', error.stack);
      throw error;
    }
  }

  /**
   * Health check for cryptographic service
   */
  public async healthCheck(): Promise<{
    status: 'healthy' | 'unhealthy';
    details: {
      hasActiveKey: boolean;
      supportedAlgorithms: string[];
      currentKeyId?: string;
      currentKeyExpiration?: Date;
    };
  }> {
    try {
      const currentKey = await this.keyStorageService.getCurrentKey();

      return {
        status: currentKey ? 'healthy' : 'unhealthy',
        details: {
          hasActiveKey: !!currentKey,
          supportedAlgorithms: this.SUPPORTED_ALGORITHMS,
          currentKeyId: currentKey?.kid,
          currentKeyExpiration: currentKey?.expiresAt,
        },
      };
    } catch (error) {
      this.logger.error('Cryptographic service health check failed', error.stack);
      return {
        status: 'unhealthy',
        details: {
          hasActiveKey: false,
          supportedAlgorithms: this.SUPPORTED_ALGORITHMS,
        },
      };
    }
  }
}
