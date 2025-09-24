// src/modules/kms/services/jwks.service.ts
import { createHash, createPublicKey } from 'crypto';

import { Injectable, Logger } from '@nestjs/common';

import { JWK, JWKS, KeyOperation } from '../interfaces/jwk.interface';

import { KeyStorageService } from './key-storage.service';

interface CertificateData {
  certificate: string;
  thumbprint: string;
  thumbprintSha256: string;
}

interface JwksMetadata {
  lastUpdated: Date;
  keyCount: number;
  nextKeyExpiry?: Date;
}

@Injectable()
export class JwksService {
  private readonly logger = new Logger(JwksService.name);

  // RFC 7517 compliant constants
  private readonly SUPPORTED_KEY_TYPES = ['RSA', 'EC', 'oct'] as const;
  private readonly SUPPORTED_ALGORITHMS = [
    'RS256',
    'RS384',
    'RS512',
    'ES256',
    'ES384',
    'ES512',
    'PS256',
    'PS384',
    'PS512',
  ] as const;
  private readonly SUPPORTED_KEY_USES = ['sig', 'enc'] as const;
  private readonly SUPPORTED_KEY_OPERATIONS: KeyOperation[] = [
    'sign',
    'verify',
    'encrypt',
    'decrypt',
    'wrapKey',
    'unwrapKey',
    'deriveKey',
    'deriveBits',
  ];

  // Current implementation defaults
  private readonly DEFAULT_ALGORITHM = 'RS256';
  private readonly KEY_TYPE = 'RSA';
  private readonly DEFAULT_KEY_OPERATIONS = ['verify'] as KeyOperation[];

  // Base64url character sets for validation
  private readonly BASE64_CHARS =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
  private readonly BASE64URL_CHARS =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  constructor(private readonly keyStorageService: KeyStorageService) {}

  /**
   * Get the JSON Web Key Set (JWKS) containing all active, non-expired public keys
   * RFC 7517 compliant implementation
   */
  public async getJwks(): Promise<JWKS> {
    try {
      const keys = await this.keyStorageService.getActiveKeys();
      const jwks: JWK[] = [];
      const errors: string[] = [];

      for (const key of keys) {
        try {
          // Double-check expiration with grace period for clock skew
          if (this.isKeyExpired(key.expiresAt, 300)) {
            // 5 minute grace period
            this.logger.debug(`Skipping expired key in JWKS: ${key.kid}`);
            continue;
          }

          const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt);

          // RFC 7517 compliant validation
          const validationResult = this.validateJwkRfc7517(jwk);
          if (validationResult.valid) {
            jwks.push(jwk);

            if (validationResult.warnings.length > 0) {
              this.logger.warn(
                `JWK warnings for ${key.kid}: ${validationResult.warnings.join(', ')}`,
              );
            }
          } else {
            errors.push(`Invalid JWK for key ${key.kid}: ${validationResult.errors.join(', ')}`);
          }
        } catch (error) {
          const errorMsg = `Failed to convert key ${key.kid} to JWK: ${this.getErrorMessage(error)}`;
          errors.push(errorMsg);
          this.logger.error(errorMsg, this.getErrorStack(error));
        }
      }

      if (errors.length > 0) {
        this.logger.warn(
          `JWKS generation completed with ${errors.length} error(s): ${errors.join('; ')}`,
        );
      }

      if (jwks.length === 0) {
        this.logger.warn(
          'No valid keys available for JWKS - this may cause authentication failures',
        );
      } else {
        this.logger.debug(`Generated RFC 7517 compliant JWKS with ${jwks.length} key(s)`);
      }

      return { keys: jwks };
    } catch (error) {
      this.logger.error('Error generating JWKS', this.getErrorStack(error));
      return { keys: [] };
    }
  }

  /**
   * Convert PEM-encoded public key to RFC 7517 compliant JWK format
   */
  private convertPemToJwk(pem: string, kid: string, expiresAt?: Date): JWK {
    try {
      if (!pem?.trim() || !kid?.trim()) {
        throw new Error('PEM content and kid are required parameters');
      }

      // Create KeyObject and validate
      const publicKey = createPublicKey(pem);

      if (publicKey.asymmetricKeyType !== 'rsa') {
        throw new Error(
          `Unsupported key type: ${publicKey.asymmetricKeyType}. Only RSA keys supported in current implementation.`,
        );
      }

      // Export as JWK to extract RSA parameters
      const keyData = publicKey.export({ format: 'jwk' }) as {
        kty?: string;
        n?: string;
        e?: string;
      };

      if (!keyData.n || !keyData.e) {
        throw new Error('Failed to extract RSA parameters (n, e) from public key');
      }

      // Validate Base64url encoding of parameters
      if (!this.isValidBase64Url(keyData.n)) {
        throw new Error('RSA modulus (n) is not valid Base64url encoded');
      }

      if (!this.isValidBase64Url(keyData.e)) {
        throw new Error('RSA exponent (e) is not valid Base64url encoded');
      }

      // Build RFC 7517 compliant JWK
      const jwk: JWK = {
        // Required parameters per RFC 7517
        kty: this.KEY_TYPE,

        // RSA-specific parameters (RFC 7518 Section 6.3)
        n: keyData.n, // Base64url-encoded modulus
        e: keyData.e, // Base64url-encoded exponent

        // Optional parameters for signature keys
        use: 'sig',
        key_ops: [...this.DEFAULT_KEY_OPERATIONS], // Copy to prevent mutation
        alg: this.DEFAULT_ALGORITHM,
        kid,
      };

      // Add expiration with proper validation
      if (expiresAt && !this.isKeyExpired(expiresAt)) {
        // RFC 7519 numeric date format (seconds since epoch)
        const expTimestamp = Math.floor(expiresAt.getTime() / 1000);

        // Validate timestamp is reasonable (not in past, not too far future)
        const now = Math.floor(Date.now() / 1000);
        if (expTimestamp > now && expTimestamp < now + 365 * 24 * 60 * 60) {
          // Within 1 year
          jwk.exp = expTimestamp;
        }
      }

      // Handle X.509 certificate data if present
      const certData = this.extractCertificateData(pem);
      if (certData) {
        jwk.x5c = [certData.certificate];
        jwk.x5t = certData.thumbprint;
        jwk['x5t#S256'] = certData.thumbprintSha256;
      }

      return jwk;
    } catch (error) {
      throw new Error(
        `PEM to JWK conversion failed for kid ${kid}: ${this.getErrorMessage(error)}`,
      );
    }
  }

  /**
   * RFC 7517 compliant JWK validation with comprehensive checks
   */
  private validateJwkRfc7517(jwk: JWK): { valid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Required parameter validation
      if (!jwk.kty) {
        errors.push('Missing required parameter: kty');
      } else if (!this.SUPPORTED_KEY_TYPES.includes(jwk.kty as any)) {
        errors.push(`Unsupported key type: ${jwk.kty}`);
      }

      // RSA-specific validation
      if (jwk.kty === 'RSA') {
        if (!jwk.n) {
          errors.push('RSA key missing required parameter: n (modulus)');
        } else if (!this.isValidBase64Url(jwk.n)) {
          errors.push('RSA modulus (n) is not valid Base64url');
        }

        if (!jwk.e) {
          errors.push('RSA key missing required parameter: e (exponent)');
        } else if (!this.isValidBase64Url(jwk.e)) {
          errors.push('RSA exponent (e) is not valid Base64url');
        }

        // Validate RSA modulus size (should be at least 2048 bits)
        if (jwk.n && this.isValidBase64Url(jwk.n)) {
          try {
            const modulusBuffer = this.base64UrlDecode(jwk.n);
            const modulusBits = modulusBuffer.length * 8;

            if (modulusBits < 2048) {
              warnings.push(`RSA modulus size ${modulusBits} bits is below recommended 2048 bits`);
            }
          } catch {
            warnings.push('Could not validate RSA modulus size');
          }
        }
      }

      // Optional parameter validation
      if (jwk.use && !this.SUPPORTED_KEY_USES.includes(jwk.use)) {
        errors.push(`Unsupported key use: ${jwk.use}`);
      }

      if (jwk.alg && !this.SUPPORTED_ALGORITHMS.includes(jwk.alg as any)) {
        warnings.push(`Algorithm ${jwk.alg} not in supported list`);
      }

      if (jwk.key_ops) {
        if (!Array.isArray(jwk.key_ops)) {
          errors.push('key_ops must be an array');
        } else {
          const invalidOps = jwk.key_ops.filter(
            (op) => !this.SUPPORTED_KEY_OPERATIONS.includes(op),
          );
          if (invalidOps.length > 0) {
            errors.push(`Unsupported key operations: ${invalidOps.join(', ')}`);
          }
        }
      }

      // Kid validation (should be present and non-empty)
      if (!jwk.kid?.trim()) {
        warnings.push('Missing kid (key ID) parameter - recommended for key identification');
      }

      // Expiration validation
      if (jwk.exp !== undefined) {
        if (typeof jwk.exp !== 'number' || !Number.isInteger(jwk.exp) || jwk.exp <= 0) {
          errors.push('exp parameter must be a positive integer (NumericDate)');
        } else {
          const now = Math.floor(Date.now() / 1000);
          if (jwk.exp <= now) {
            errors.push(`Key is expired (exp: ${jwk.exp}, now: ${now})`);
          }
        }
      }

      // Not before validation
      if (jwk.nbf !== undefined) {
        if (typeof jwk.nbf !== 'number' || !Number.isInteger(jwk.nbf) || jwk.nbf < 0) {
          errors.push('nbf parameter must be a non-negative integer (NumericDate)');
        } else {
          const now = Math.floor(Date.now() / 1000);
          if (jwk.nbf > now) {
            warnings.push(`Key is not yet valid (nbf: ${jwk.nbf}, now: ${now})`);
          }
        }
      }

      // X.509 certificate chain validation
      if (jwk.x5c) {
        if (!Array.isArray(jwk.x5c)) {
          errors.push('x5c must be an array of certificate strings');
        } else {
          jwk.x5c.forEach((cert, index) => {
            if (!this.isValidBase64(cert)) {
              errors.push(`Invalid base64 certificate at index ${index} in x5c`);
            }
          });
        }
      }

      // X.509 thumbprint validation
      if (jwk.x5t && !this.isValidBase64Url(jwk.x5t)) {
        errors.push('x5t thumbprint is not valid Base64url');
      }

      if (jwk['x5t#S256'] && !this.isValidBase64Url(jwk['x5t#S256'])) {
        errors.push('x5t#S256 thumbprint is not valid Base64url');
      }

      // Consistency checks
      if (jwk.use && jwk.key_ops) {
        const useConsistent = this.validateUseKeyOpsConsistency(jwk.use, jwk.key_ops);
        if (!useConsistent) {
          warnings.push('use and key_ops parameters may be inconsistent');
        }
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings,
      };
    } catch (error) {
      errors.push(`Validation error: ${this.getErrorMessage(error)}`);
      return { valid: false, errors, warnings };
    }
  }

  /**
   * Validate consistency between 'use' and 'key_ops' parameters
   * RFC 7517 Section 4.2 and 4.3
   */
  private validateUseKeyOpsConsistency(use: string, keyOps: KeyOperation[]): boolean {
    if (use === 'sig') {
      return keyOps.every((op) => ['sign', 'verify'].includes(op));
    } else if (use === 'enc') {
      return keyOps.every((op) =>
        ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'].includes(op),
      );
    }
    return true; // Unknown use value, can't validate consistency
  }

  /**
   * Enhanced Base64url validation per RFC 4648 Section 5
   */
  private isValidBase64Url(str: string): boolean {
    if (!str || typeof str !== 'string') return false;

    // Base64url uses A-Z, a-z, 0-9, -, _ (no padding)
    const base64UrlPattern = /^[A-Za-z0-9_-]+$/;

    if (!base64UrlPattern.test(str)) return false;

    // Additional length validation - must be valid for base64 decoding
    try {
      this.base64UrlDecode(str);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * RFC 4648 compliant Base64url decoding
   */
  private base64UrlDecode(str: string): Buffer {
    // Convert Base64url to standard Base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if necessary
    const padding = 4 - (base64.length % 4);
    if (padding !== 4) {
      base64 += '='.repeat(padding);
    }

    return Buffer.from(base64, 'base64');
  }

  /**
   * Enhanced Base64 validation for standard encoding
   */
  private isValidBase64(str: string): boolean {
    if (!str || typeof str !== 'string') return false;

    // Standard base64 pattern with optional padding
    const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;

    if (!base64Pattern.test(str)) return false;

    try {
      Buffer.from(str, 'base64');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Enhanced certificate data extraction with proper validation
   */
  private extractCertificateData(pemData: string): CertificateData | null {
    try {
      const certMatch = pemData.match(
        /-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/,
      );

      if (!certMatch || !certMatch[1]) {
        this.logger.debug('PEM data is not a certificate, skipping X.509 fields');
        return null;
      }

      // Extract and validate base64 certificate data
      const certBase64 = certMatch[1].replace(/\s+/g, '');

      if (!this.isValidBase64(certBase64)) {
        this.logger.warn('Invalid base64 certificate data detected');
        return null;
      }

      // Convert to DER format
      const certDer = Buffer.from(certBase64, 'base64');

      // Basic ASN.1 DER validation
      if (certDer.length < 100 || certDer[0] !== 0x30) {
        this.logger.warn('Certificate data appears invalid or corrupted');
        return null;
      }

      // Generate RFC 7517 compliant thumbprints
      const sha1Hash = createHash('sha1').update(certDer).digest();
      const sha256Hash = createHash('sha256').update(certDer).digest();

      return {
        certificate: certBase64,
        thumbprint: this.base64UrlEncode(sha1Hash),
        thumbprintSha256: this.base64UrlEncode(sha256Hash),
      };
    } catch (error) {
      this.logger.warn('Failed to extract certificate data', this.getErrorStack(error));
      return null;
    }
  }

  /**
   * RFC 4648 compliant Base64url encoding
   */
  private base64UrlEncode(buffer: Buffer): string {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Enhanced key expiration check with configurable grace period
   */
  private isKeyExpired(expiresAt?: Date, gracePeriodSeconds: number = 0): boolean {
    if (!expiresAt) return false;

    const now = new Date();
    const expiryWithGrace = new Date(expiresAt.getTime() + gracePeriodSeconds * 1000);

    return now > expiryWithGrace;
  }

  /**
   * Get JWKS with metadata for monitoring and caching
   */
  public async getJwksWithMetadata(): Promise<{ jwks: JWKS; metadata: JwksMetadata }> {
    const jwks = await this.getJwks();
    const keys = await this.keyStorageService.getActiveKeys();

    const nextExpiry = keys.reduce(
      (earliest, key) => {
        if (!earliest || key.expiresAt < earliest) {
          return key.expiresAt;
        }
        return earliest;
      },
      null as Date | null,
    );

    const metadata: JwksMetadata = {
      lastUpdated: new Date(),
      keyCount: jwks.keys.length,
      nextKeyExpiry: nextExpiry || undefined,
    };

    return { jwks, metadata };
  }

  /**
   * Get JWKS statistics for enhanced monitoring
   */
  public async getJwksStats(): Promise<{
    totalKeys: number;
    validKeys: number;
    expiredKeys: number;
    certificateKeys: number;
    algorithmDistribution: Record<string, number>;
  }> {
    try {
      const { jwks } = await this.getJwksWithMetadata();
      const validKeys = jwks.keys.filter((jwk) => this.validateJwkRfc7517(jwk).valid);

      const algorithmDistribution: Record<string, number> = {};
      jwks.keys.forEach((jwk) => {
        const alg = jwk.alg || 'unknown';
        algorithmDistribution[alg] = (algorithmDistribution[alg] || 0) + 1;
      });

      const now = Math.floor(Date.now() / 1000);
      const expiredKeys = jwks.keys.filter((jwk) => jwk.exp && jwk.exp < now);
      const certificateKeys = jwks.keys.filter((jwk) => jwk.x5c && jwk.x5c.length > 0);

      return {
        totalKeys: jwks.keys.length,
        validKeys: validKeys.length,
        expiredKeys: expiredKeys.length,
        certificateKeys: certificateKeys.length,
        algorithmDistribution,
      };
    } catch (error) {
      this.logger.error('Error getting JWKS statistics', this.getErrorStack(error));
      return {
        totalKeys: 0,
        validKeys: 0,
        expiredKeys: 0,
        certificateKeys: 0,
        algorithmDistribution: {},
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
