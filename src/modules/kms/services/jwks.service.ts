import { createHash, createPublicKey } from 'crypto';

import { Injectable, Logger } from '@nestjs/common';

import { JWK, JWKS, KeyOperation } from '../interfaces/jwk.interface';

import { KeyStorageService } from './key-storage.service';

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
  private readonly KEY_OPERATIONS = ['verify'];

  constructor(private readonly keyStorageService: KeyStorageService) {}

  /**
   * Get the JSON Web Key Set (JWKS) containing all active, non-expired public keys
   */
  public async getJwks(): Promise<JWKS> {
    try {
      // Get only active, non-expired keys
      const keys = await this.keyStorageService.getActiveKeys();
      const jwks: JWK[] = [];

      for (const key of keys) {
        try {
          // Double-check expiration (defense in depth)
          if (this.isKeyExpired(key.expiresAt)) {
            this.logger.debug(`Skipping expired key in JWKS: ${key.kid}`);
            continue;
          }

          const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt);

          // Validate JWK before including
          if (this.validateJwk(jwk)) {
            jwks.push(jwk);
          } else {
            this.logger.warn(`Invalid JWK generated for key: ${key.kid}`);
          }
        } catch (error) {
          this.logger.error(
            `Failed to convert key ${key.kid} to JWK format`,
            this.getErrorStack(error),
          );
          // Continue with other keys if one fails
        }
      }

      if (jwks.length === 0) {
        this.logger.warn(
          'No valid keys available for JWKS - this may cause authentication failures',
        );
      } else {
        this.logger.debug(`Generated JWKS with ${jwks.length} key(s)`);
      }

      return { keys: jwks };
    } catch (error) {
      this.logger.error('Error generating JWKS', this.getErrorStack(error));
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
   * Convert a PEM-encoded public key to JWK format with proper RSA parameter extraction
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

      // Create base JWK
      const jwk: JWK = {
        kty: this.KEY_TYPE,
        use: 'sig',
        kid,
        alg: this.DEFAULT_ALGORITHM,
        n: keyData.n, // Base64url-encoded modulus
        e: keyData.e, // Base64url-encoded exponent
        key_ops: [...this.KEY_OPERATIONS] as KeyOperation[], // Copy array to avoid mutations
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
      // More robust certificate detection
      const isCertificate =
        pemData.includes('-----BEGIN CERTIFICATE-----') &&
        pemData.includes('-----END CERTIFICATE-----');

      if (!isCertificate) {
        // This is expected for raw public keys
        this.logger.debug('PEM data is not a certificate, skipping X.509 fields');
        return null;
      }

      // Extract the base64 certificate data (remove headers, footers, and whitespace)
      const certBase64 = pemData
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');

      // Validate base64 format
      if (!this.isValidBase64(certBase64)) {
        this.logger.warn('Invalid base64 certificate data detected');
        return null;
      }

      // Convert to DER format (binary)
      const certDer = Buffer.from(certBase64, 'base64');

      // Validate minimum certificate size (typical X.509 certs are at least 200+ bytes)
      if (certDer.length < 100) {
        this.logger.warn(
          `Certificate data appears too small (${certDer.length} bytes) to be valid`,
        );
        return null;
      }

      // Basic ASN.1 structure validation - check for DER sequence header
      if (certDer[0] !== 0x30) {
        this.logger.warn('Certificate data does not appear to be valid ASN.1 DER format');
        return null;
      }

      // Generate SHA-1 thumbprint (x5t) - Base64url encoded
      const sha1Thumbprint = createHash('sha1').update(certDer).digest('base64url');

      // Generate SHA-256 thumbprint (x5t#S256) - Base64url encoded
      const sha256Thumbprint = createHash('sha256').update(certDer).digest('base64url');

      return {
        certificate: certBase64, // Standard base64 (not base64url) for x5c
        thumbprint: sha1Thumbprint,
        thumbprintSha256: sha256Thumbprint,
      };
    } catch (error) {
      this.logger.warn('Failed to generate certificate data', this.getErrorStack(error));
      return null;
    }
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
   * Validate JWK structure according to RFC 7517
   */
  public validateJwk(jwk: JWK): boolean {
    try {
      // Check required fields for RSA keys used for signing
      const requiredFields = ['kty', 'use', 'kid', 'alg', 'n', 'e'] as const;

      for (const field of requiredFields) {
        if (!(field in jwk) || !jwk[field]) {
          this.logger.error(`JWK validation failed: Missing or empty required field: ${field}`);
          return false;
        }
      }

      // Validate specific values
      if (jwk.kty !== 'RSA') {
        this.logger.error(`JWK validation failed: Invalid key type: ${jwk.kty}, expected RSA`);
        return false;
      }

      if (jwk.use !== 'sig') {
        this.logger.error(`JWK validation failed: Invalid use: ${jwk.use}, expected sig`);
        return false;
      }

      if (jwk.alg !== 'RS256') {
        this.logger.error(`JWK validation failed: Invalid algorithm: ${jwk.alg}, expected RS256`);
        return false;
      }

      // Validate Base64url encoding of n and e
      if (!this.isValidBase64Url(jwk.n as string)) {
        this.logger.error('JWK validation failed: Invalid Base64url encoding for modulus (n)');
        return false;
      }

      if (!this.isValidBase64Url(jwk.e as string)) {
        this.logger.error('JWK validation failed: Invalid Base64url encoding for exponent (e)');
        return false;
      }

      // Validate key_ops if present
      if (jwk.key_ops && Array.isArray(jwk.key_ops)) {
        const validOps = [
          'verify',
          'sign',
          'encrypt',
          'decrypt',
          'wrapKey',
          'unwrapKey',
          'deriveKey',
          'deriveBits',
        ];
        for (const op of jwk.key_ops) {
          if (!validOps.includes(op)) {
            this.logger.error(`JWK validation failed: Invalid key operation: ${op}`);
            return false;
          }
        }
      }

      // Validate expiration if present
      if (jwk.exp !== undefined) {
        if (typeof jwk.exp !== 'number' || jwk.exp <= 0) {
          this.logger.error(`JWK validation failed: Invalid expiration time: ${jwk.exp}`);
          return false;
        }

        // Check if expired
        const now = Math.floor(Date.now() / 1000);
        if (jwk.exp < now) {
          this.logger.error(`JWK validation failed: Key is expired (exp: ${jwk.exp}, now: ${now})`);
          return false;
        }
      }

      // Validate certificate fields if present
      if (jwk.x5c && Array.isArray(jwk.x5c)) {
        for (const cert of jwk.x5c) {
          if (!this.isValidBase64(cert)) {
            this.logger.error('JWK validation failed: Invalid certificate in x5c');
            return false;
          }
        }
      }

      if (jwk.x5t && !this.isValidBase64Url(jwk.x5t)) {
        this.logger.error('JWK validation failed: Invalid x5t thumbprint');
        return false;
      }

      if (jwk['x5t#S256'] && !this.isValidBase64Url(jwk['x5t#S256'])) {
        this.logger.error('JWK validation failed: Invalid x5t#S256 thumbprint');
        return false;
      }

      return true;
    } catch (error) {
      this.logger.error('Error validating JWK', this.getErrorStack(error));
      return false;
    }
  }

  /**
   * Validate Base64url encoding (RFC 4648 Section 5)
   */
  private isValidBase64Url(str: string): boolean {
    try {
      if (!str || str.length === 0) return false;

      // Base64url uses A-Z, a-z, 0-9, -, _ and no padding
      const base64UrlRegex = /^[A-Za-z0-9_-]+$/;

      if (!base64UrlRegex.test(str)) return false;

      // Additional validation: convert to standard base64 and try to decode
      const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const padded = base64 + '==='.slice(0, (4 - (base64.length % 4)) % 4);

      Buffer.from(padded, 'base64');
      return true;
    } catch {
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
      const validKeys = jwks.keys.filter((jwk) => this.validateJwk(jwk)).length;
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
