import { createHash, createPublicKey } from 'crypto';

import { Injectable, Logger } from '@nestjs/common';

import {
  JWKSUnavailableException,
  JWKValidationException,
} from '@/shared/exceptions/jwk.exception';

import { JWK, JWKS, KeyOperation } from '../interfaces/jwk.interface';

import { KeyStorageService } from './key-storage.service';

export interface RsaJwk extends JWK {
  kty: 'RSA';
  use: 'sig' | 'enc';
  alg: 'RS256' | 'RS384' | 'RS512';
  n: string;
  e: string;
  exp?: number;
}

interface StoredKey {
  kid: string;
  publicKey: string;
  expiresAt?: Date;
  alg?: 'RS256' | 'RS384' | 'RS512';
  algorithm?: 'RS256' | 'RS384' | 'RS512';
}

@Injectable()
export class JwksService {
  private readonly logger = new Logger(JwksService.name);
  private readonly DEFAULT_ALGORITHM: RsaJwk['alg'] = 'RS256';
  private readonly KEY_TYPE: RsaJwk['kty'] = 'RSA';
  private readonly KEY_OPERATIONS: KeyOperation[] = ['verify'];

  constructor(private readonly keyStorageService: KeyStorageService) {}

  /**
   * Get the JSON Web Key Set (JWKS) containing all active, non-expired public keys
   */
  public async getJwks(): Promise<JWKS> {
    try {
      const keys = (await this.keyStorageService.getActiveKeys()) as StoredKey[];
      const jwks: RsaJwk[] = [];
      const validationErrors: string[] = [];

      for (const key of keys) {
        try {
          if (this.isKeyExpired(key.expiresAt)) {
            this.logger.debug(`Skipping expired key in JWKS: ${key.kid}`);
            continue;
          }

          const alg = key.alg ?? key.algorithm ?? this.DEFAULT_ALGORITHM;
          const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt, alg);

          const validation = this.validateJwk(jwk);
          if (validation.valid) {
            jwks.push(jwk);
          } else {
            this.logger.warn(`Invalid JWK for key ${key.kid}: ${validation.errors.join(', ')}`);
            validationErrors.push(...validation.errors.map((err) => `${key.kid}: ${err}`));
          }
        } catch (error) {
          this.logger.error(
            `Failed to convert key ${key.kid} to JWK format`,
            this.getErrorStack(error),
          );

          const errorMessage = this.getErrorMessage(error);
          validationErrors.push(`${key.kid}: Conversion failed - ${errorMessage}`);
        }
      }

      if (jwks.length === 0 && keys.length > 0) {
        throw new JWKSUnavailableException(
          `All keys failed validation: ${validationErrors.join('; ')}`,
        );
      }

      if (jwks.length === 0) {
        this.logger.warn('No valid keys available for JWKS');
      } else {
        this.logger.debug(`Generated JWKS with ${jwks.length} key(s)`);
      }

      return { keys: jwks };
    } catch (error) {
      if (error instanceof JWKSUnavailableException) {
        throw error;
      }

      this.logger.error('Error generating JWKS', this.getErrorStack(error));
      throw new JWKSUnavailableException('JWKS generation failed');
    }
  }

  /**
   * Get the JWK for a specific key ID
   */
  public async getJwk(kid: string): Promise<RsaJwk | null> {
    try {
      const key = (await this.keyStorageService.getValidatedKey(kid)) as StoredKey | null; // <- NEW METHOD
      if (!key) {
        this.logger.debug(`Key not found or invalid: ${kid}`);
        return null;
      }

      const alg = key.alg ?? key.algorithm ?? this.DEFAULT_ALGORITHM;
      const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt, alg);

      const validation = this.validateJwk(jwk);
      if (!validation.valid) {
        throw new JWKValidationException(validation.errors.map((err) => `${kid}: ${err}`));
      }

      return jwk;
    } catch (error) {
      if (error instanceof JWKValidationException) throw error;

      this.logger.error(`Error getting JWK for key ${kid}`, this.getErrorStack(error));
      return null;
    }
  }

  /**
   * Convert a PEM-encoded public key or certificate (chain) to JWK format
   */
  private convertPemToJwk(
    pem: string,
    kid: string,
    expiresAt: Date | undefined,
    alg: RsaJwk['alg'],
  ): RsaJwk {
    try {
      if (!pem || !kid) {
        throw new Error('PEM and kid are required parameters');
      }

      const publicKey = createPublicKey(pem);
      if (publicKey.asymmetricKeyType !== 'rsa') {
        throw new Error(`Unsupported key type: ${publicKey.asymmetricKeyType}`);
      }

      const keyData = publicKey.export({ format: 'jwk' }) as {
        kty?: string;
        n?: string;
        e?: string;
      };

      if (!keyData.n || !keyData.e) {
        throw new Error('Failed to extract RSA modulus (n) or exponent (e)');
      }

      // Determine appropriate key operations for signing keys
      const keyOps: KeyOperation[] = ['verify']; // Public keys are for verification

      const jwk: RsaJwk = {
        kty: this.KEY_TYPE,
        use: 'sig' as const, // Explicitly cast to satisfy the type
        kid,
        alg,
        n: keyData.n,
        e: keyData.e,
        key_ops: keyOps,
      };

      // Add expiration if key has valid expiry date
      if (expiresAt && !this.isKeyExpired(expiresAt)) {
        jwk.exp = Math.floor(expiresAt.getTime() / 1000);
      }

      // Add X.509 certificate information if available
      const certs = this.extractCertificates(pem);
      if (certs.length > 0) {
        jwk.x5c = certs;

        // Generate thumbprints only for valid certificates
        try {
          jwk.x5t = this.generateThumbprint(certs[0], 'sha1');
          jwk['x5t#S256'] = this.generateThumbprint(certs[0], 'sha256');
        } catch (error) {
          this.logger.warn(
            `Failed to generate certificate thumbprints for ${kid}:`,
            this.getErrorStack(error),
          );
        }
      }

      return jwk;
    } catch (error) {
      this.logger.error(`Error converting PEM to JWK for kid: ${kid}`, this.getErrorStack(error));
      throw new Error(`Failed to convert public key to JWK format: ${this.getErrorMessage(error)}`);
    }
  }

  private extractCertificates(pemData: string): string[] {
    const certBegin = '-----BEGIN CERTIFICATE-----';
    const certEnd = '-----END CERTIFICATE-----';

    if (!pemData.includes(certBegin)) {
      return [];
    }

    const certs: string[] = [];
    const parts = pemData.split(certEnd);

    for (const part of parts) {
      if (!part.includes(certBegin)) continue;
      const block = part.substring(part.indexOf(certBegin) + certBegin.length);
      const base64 = block.replace(/[\r\n\s]/g, '');
      if (this.isValidBase64(base64)) {
        certs.push(base64);
      }
    }

    return certs;
  }

  private generateThumbprint(certBase64: string, algo: 'sha1' | 'sha256'): string {
    const der = Buffer.from(certBase64, 'base64');
    return createHash(algo).update(der).digest('base64url');
  }

  private isKeyExpired(expiresAt?: Date): boolean {
    return !!expiresAt && new Date() > expiresAt;
  }

  public validateJwk(jwk: RsaJwk): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Required parameters for RSA keys (RFC 7517 Section 6.3.1)
    const requiredFields: (keyof Pick<RsaJwk, 'kty' | 'n' | 'e'>)[] = ['kty', 'n', 'e'];

    for (const field of requiredFields) {
      if (!jwk[field]) {
        errors.push(`Missing required parameter: ${field}`);
      }
    }

    // Key type validation - use string conversion to avoid template literal type error
    if (jwk.kty !== 'RSA') {
      errors.push(`Invalid key type: ${String(jwk.kty)}. Expected 'RSA'`);
    }

    // Algorithm validation (if present)
    if (jwk.alg && !['RS256', 'RS384', 'RS512'].includes(jwk.alg)) {
      errors.push(`Unsupported algorithm: ${jwk.alg}`);
    }

    // Key usage validation (if present)
    if (jwk.use && !['sig', 'enc'].includes(jwk.use)) {
      errors.push(`Invalid key use: ${jwk.use}. Must be 'sig' or 'enc'`);
    }

    // Key operations validation (if present)
    if (jwk.key_ops) {
      const validOps = [
        'sign',
        'verify',
        'encrypt',
        'decrypt',
        'wrapKey',
        'unwrapKey',
        'deriveKey',
        'deriveBits',
      ];
      const invalidOps = jwk.key_ops.filter((op) => !validOps.includes(op));
      if (invalidOps.length > 0) {
        errors.push(`Invalid key operations: ${invalidOps.join(', ')}`);
      }

      // Validate key_ops and use consistency (RFC 7517 Section 4.3)
      if (jwk.use === 'sig' && jwk.key_ops.some((op) => !['sign', 'verify'].includes(op))) {
        errors.push("Key operations inconsistent with 'sig' usage");
      }
      if (
        jwk.use === 'enc' &&
        jwk.key_ops.some((op) => !['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'].includes(op))
      ) {
        errors.push("Key operations inconsistent with 'enc' usage");
      }
    }

    // Base64URL validation for RSA parameters
    if (jwk.n && !this.isValidBase64Url(jwk.n)) {
      errors.push('Invalid base64url encoding for modulus (n)');
    }

    if (jwk.e && !this.isValidBase64Url(jwk.e)) {
      errors.push('Invalid base64url encoding for exponent (e)');
    }

    // X.509 certificate chain validation (if present)
    if (jwk.x5c) {
      if (!Array.isArray(jwk.x5c) || jwk.x5c.length === 0) {
        errors.push('x5c must be a non-empty array of certificates');
      } else {
        for (let i = 0; i < jwk.x5c.length; i++) {
          if (!this.isValidBase64(jwk.x5c[i])) {
            errors.push(`Invalid base64 encoding for certificate at index ${i}`);
          } else if (!this.validateCertificateFormat(jwk.x5c[i])) {
            errors.push(`Invalid certificate format at index ${i}`);
          }
        }
      }
    }

    // X.509 thumbprint validation (if present)
    if (jwk.x5t && !this.isValidBase64Url(jwk.x5t)) {
      errors.push('Invalid base64url encoding for x5t');
    }

    if (jwk['x5t#S256'] && !this.isValidBase64Url(jwk['x5t#S256'])) {
      errors.push('Invalid base64url encoding for x5t#S256');
    }

    // RSA key strength validation (if n and e are valid)
    if (
      jwk.n &&
      jwk.e &&
      errors.filter((e) => e.includes('modulus') || e.includes('exponent')).length === 0
    ) {
      if (!this.validateRsaKeyStrength(jwk.n, jwk.e)) {
        errors.push('RSA key does not meet minimum security requirements');
      }
    }

    // Lifecycle parameters validation (if present)
    if (jwk.nbf && typeof jwk.nbf !== 'number') {
      errors.push('nbf (not before) must be a number');
    }

    if (jwk.exp && typeof jwk.exp !== 'number') {
      errors.push('exp (expiration) must be a number');
    }

    if (jwk.nbf && jwk.exp && jwk.nbf >= jwk.exp) {
      errors.push('nbf (not before) must be less than exp (expiration)');
    }

    return { valid: errors.length === 0, errors };
  }

  private validateCertificateFormat(certBase64: string): boolean {
    try {
      const der = Buffer.from(certBase64, 'base64');

      // Minimum reasonable certificate size
      if (der.length < 100) {
        return false;
      }

      // DER structure must start with SEQUENCE (0x30)
      if (der[0] !== 0x30) {
        return false;
      }

      // Basic length validation - ensure the length field is reasonable
      if (der.length < 4) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  private validateRsaKeyStrength(nBase64Url: string, eBase64Url: string): boolean {
    const nBuffer = this.base64UrlToBuffer(nBase64Url);
    const eBuffer = this.base64UrlToBuffer(eBase64Url);

    const keySizeBits = nBuffer.length * 8;
    if (keySizeBits < 2048) {
      this.logger.error(`RSA key too small: ${keySizeBits} bits`);
      return false;
    }

    let exponent = 0;
    for (let i = 0; i < eBuffer.length; i++) {
      exponent = (exponent << 8) + eBuffer[i];
    }

    if (exponent % 2 === 0) {
      this.logger.error('RSA exponent must be odd');
      return false;
    }

    return true;
  }

  private base64UrlToBuffer(b64Url: string): Buffer {
    const base64 = b64Url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '==='.slice(0, (4 - (base64.length % 4)) % 4);
    return Buffer.from(padded, 'base64');
  }

  private isValidBase64(str: string): boolean {
    return /^[A-Za-z0-9+/]+={0,2}$/.test(str);
  }

  private isValidBase64Url(str: string): boolean {
    return /^[A-Za-z0-9_-]+$/.test(str);
  }

  private getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message || 'Unknown error';
    }
    if (typeof error === 'string') {
      return error;
    }
    return 'Unknown error';
  }

  private getErrorStack(error: unknown): string {
    if (error instanceof Error) {
      return error.stack || error.message || 'Unknown error';
    }
    if (typeof error === 'string') {
      return error;
    }
    return String(error);
  }
}
