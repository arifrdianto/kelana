import { createHash, createPublicKey } from 'crypto';

import { Injectable, Logger } from '@nestjs/common';

import { JWK, JWKS, KeyOperation } from '../interfaces/jwk.interface';

import { KeyStorageService } from './key-storage.service';
import { KeyValidationService } from './key-validation.service';

interface CertificateData {
  certificate: string;
  thumbprint: string;
  thumbprintSha256: string;
}

@Injectable()
export class JwksService {
  private readonly logger = new Logger(JwksService.name);
  private readonly DEFAULT_ALGORITHM = 'RS256';
  private readonly KEY_TYPE = 'RSA';
  private readonly SIGNING_KEY_OPERATIONS: KeyOperation[] = ['sign', 'verify'];

  constructor(
    private readonly keyStorageService: KeyStorageService,
    private readonly keyValidationService: KeyValidationService,
  ) {}

  /**
   * Get the JSON Web Key Set (JWKS) containing all active, non-expired public keys
   */
  public async getJwks(): Promise<JWKS> {
    try {
      const keys = await this.keyStorageService.getActiveKeys();
      const jwks: JWK[] = [];

      for (const key of keys) {
        try {
          // Skip expired keys explicitly
          if (this.isKeyExpired(key.expiresAt)) {
            this.logger.debug(`Skipping expired key: ${key.kid}`);
            continue;
          }

          const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt);
          if (this.validateJwk(jwk)) {
            jwks.push(jwk);
          } else {
            this.logger.warn(`Generated JWK for key ${key.kid} failed validation`);
          }
        } catch (error) {
          this.logger.error(`Failed to convert key ${key.kid} to JWK`, error);
        }
      }

      this.logger.debug(`Generated JWKS with ${jwks.length} valid keys`);
      return { keys: jwks };
    } catch (error) {
      this.logger.error('Error generating JWKS', error);
      return { keys: [] };
    }
  }

  /**
   * Get the JWK for a specific key ID
   */
  public async getJwk(kid: string): Promise<JWK | null> {
    try {
      const key = await this.keyStorageService.getKey(kid);
      if (!key) {
        this.logger.debug(`Key not found: ${kid}`);
        return null;
      }

      if (this.isKeyExpired(key.expiresAt)) {
        this.logger.warn(`Requested key is expired: ${kid}`);
        return null;
      }

      const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt);

      if (!this.validateJwk(jwk)) {
        this.logger.error(`Generated invalid JWK for key: ${kid}`);
        return null;
      }

      return jwk;
    } catch (error) {
      this.logger.error(`Error getting JWK for key ${kid}`, this.getErrorStack(error));
      return null;
    }
  }

  /**
   * Convert a PEM-encoded public key to RFC 7517 compliant JWK format
   */
  private convertPemToJwk(pem: string, kid: string, expiresAt?: Date): JWK {
    try {
      // Validate input
      if (!pem || !kid) {
        throw new Error('PEM and kid are required parameters');
      }

      // Create a crypto KeyObject from the PEM
      const publicKey = createPublicKey(pem);

      // Verify it's an RSA key
      if (publicKey.asymmetricKeyType !== 'rsa') {
        throw new Error(
          `Unsupported key type: ${publicKey.asymmetricKeyType}. Only RSA keys are supported.`,
        );
      }

      // Export as JWK to get proper n and e values
      const keyData = publicKey.export({ format: 'jwk' }) as {
        kty?: string;
        n?: string;
        e?: string;
      };

      if (!keyData.n || !keyData.e) {
        throw new Error('Failed to extract RSA modulus (n) or exponent (e) from public key');
      }

      // RFC 7517 compliant JWK creation
      const now = Math.floor(Date.now() / 1000);
      const jwk: JWK = {
        kty: 'RSA',
        use: 'sig',
        kid,
        alg: this.DEFAULT_ALGORITHM,
        n: keyData.n,
        e: keyData.e,
        key_ops: [...this.SIGNING_KEY_OPERATIONS], // RFC 7517 Section 4.3
        nbf: now, // RFC 7517 Section 4.6 - not before timestamp
      };

      // Add expiration if available and not already expired
      if (expiresAt && !this.isKeyExpired(expiresAt)) {
        jwk.exp = Math.floor(expiresAt.getTime() / 1000);
      }

      // Handle X.509 certificate data if present
      const certData = this.generateCertificateData(pem);
      if (certData) {
        jwk.x5c = [certData.certificate];
        jwk.x5t = certData.thumbprint;
        jwk['x5t#S256'] = certData.thumbprintSha256;
      }

      return jwk;
    } catch (error) {
      this.logger.error(`Error converting PEM to JWK for kid: ${kid}`, this.getErrorStack(error));
      throw new Error(
        `Failed to convert public key to JWK format: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  /**
   * Generate certificate data for X.509 fields from a PEM certificate
   * Enhanced version with better validation and error handling
   */
  private generateCertificateData(pemData: string): CertificateData | null {
    try {
      const isCertificate = this.isCertificate(pemData);

      if (!isCertificate) {
        return null;
      }

      const certBase64 = this.extractCertificateBase64(pemData);

      if (!this.isValidBase64(certBase64)) {
        throw new Error('Invalid certificate Base64 encoding');
      }

      const certDer = Buffer.from(certBase64, 'base64');

      // Validate certificate isn't obviously malformed
      if (certDer.length < 100) {
        throw new Error('Certificate appears to be too small to be valid');
      }

      return {
        certificate: certBase64,
        thumbprint: createHash('sha1').update(certDer).digest('base64url'),
        thumbprintSha256: createHash('sha256').update(certDer).digest('base64url'),
      };
    } catch (error) {
      this.logger.warn('Failed to process certificate data', error);
      return null;
    }
  }

  /**
   * Check if PEM data contains a certificate
   */
  private isCertificate(pemData: string): boolean {
    return (
      pemData.includes('-----BEGIN CERTIFICATE-----') &&
      pemData.includes('-----END CERTIFICATE-----')
    );
  }

  /**
   * Extract base64 data from PEM certificate
   */
  private extractCertificateBase64(pemData: string): string {
    return pemData
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
  }

  /**
   * Validate standard Base64 encoding (with padding)
   */
  private isValidBase64(str: string): boolean {
    try {
      if (!str || str.length === 0) return false;

      // Base64 uses A-Z, a-z, 0-9, +, / and = for padding
      const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;

      if (!base64Regex.test(str)) return false;

      // Additional validation: try to decode it
      Buffer.from(str, 'base64');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get the current active JWK
   */
  public async getCurrentJwk(): Promise<JWK | null> {
    try {
      const key = await this.keyStorageService.getCurrentKey();
      if (!key) {
        this.logger.debug('No current active key found');
        return null;
      }

      if (this.isKeyExpired(key.expiresAt)) {
        this.logger.warn(`Current key is expired: ${key.kid}`);
        return null;
      }

      const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt);

      if (!this.validateJwk(jwk)) {
        this.logger.error('Current key generated invalid JWK');
        return null;
      }

      return jwk;
    } catch (error) {
      this.logger.error('Error getting current JWK', this.getErrorStack(error));
      return null;
    }
  }

  /**
   * Check if a key is expired
   */
  private isKeyExpired(expiresAt?: Date): boolean {
    if (!expiresAt) return false;
    return new Date() > expiresAt;
  }

  /**
   * Validate JWK using the comprehensive KeyValidationService
   */
  public validateJwk(jwk: JWK): boolean {
    try {
      const result = this.keyValidationService.validateJWK(jwk);

      if (!result.valid) {
        this.logger.error(`JWK validation failed: ${result.errors.join(', ')}`);
        return false;
      }

      if (result.warnings.length > 0) {
        this.logger.warn(`JWK validation warnings: ${result.warnings.join(', ')}`);
      }

      return true;
    } catch (error) {
      this.logger.error('Error validating JWK', this.getErrorStack(error));
      return false;
    }
  }

  /**
   * Get JWKS statistics for monitoring
   */
  public async getJwksStats(): Promise<{
    totalKeys: number;
    validKeys: number;
    expiredKeys: number;
    certificateKeys: number;
  }> {
    try {
      const jwks = await this.getJwks();
      const totalKeys = jwks.keys.length;

      // All keys from getJwks() are already validated
      const validKeys = totalKeys;

      const expiredKeys = jwks.keys.filter(
        (jwk) => jwk.exp && jwk.exp < Math.floor(Date.now() / 1000),
      ).length;

      const certificateKeys = jwks.keys.filter((jwk) => jwk.x5c && jwk.x5c.length > 0).length;

      return {
        totalKeys,
        validKeys,
        expiredKeys,
        certificateKeys,
      };
    } catch (error) {
      this.logger.error('Error getting JWKS statistics', this.getErrorStack(error));
      return {
        totalKeys: 0,
        validKeys: 0,
        expiredKeys: 0,
        certificateKeys: 0,
      };
    }
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
