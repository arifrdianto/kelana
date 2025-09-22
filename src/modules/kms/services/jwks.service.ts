import { createHash, createPublicKey } from 'crypto';

import { Injectable, Logger } from '@nestjs/common';

import { KeyStorageService } from './key-storage.service';

export interface JWK {
  kty: string;
  use: string;
  kid: string;
  alg: string;
  n: string;
  e: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;
  key_ops?: string[];
  nbf?: number;
  exp?: number;
}

export interface JWKS {
  keys: JWK[];
}

@Injectable()
export class JwksService {
  private readonly logger = new Logger(JwksService.name);
  private readonly DEFAULT_ALGORITHM = 'RS256';
  private readonly KEY_TYPE = 'RSA';
  private readonly KEY_OPERATIONS = ['verify'];

  constructor(private readonly keyStorageService: KeyStorageService) {}

  /**
   * Get the JSON Web Key Set (JWKS) containing all active public keys
   */
  public async getJwks(): Promise<JWKS> {
    try {
      // Only get active keys for JWKS
      const keys = await this.keyStorageService.getActiveKeys();
      const jwks: JWK[] = [];

      for (const key of keys) {
        try {
          // Skip expired keys
          if (this.isKeyExpired(key.expiresAt)) {
            this.logger.warn(`Skipping expired key: ${key.kid}`);
            continue;
          }

          const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt);
          jwks.push(jwk);
        } catch (error) {
          this.logger.error(
            `Failed to convert key ${key.kid} to JWK format`,
            this.getErrorStack(error),
          );
          // Continue with other keys if one fails
        }
      }

      if (jwks.length === 0) {
        this.logger.warn('No valid keys available for JWKS');
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
        this.logger.warn(`Key expired: ${kid}`);
        return null;
      }

      return this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt);
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
        key_ops: [...this.KEY_OPERATIONS], // Copy array to avoid mutations
      };

      // Add expiration if available
      if (expiresAt) {
        jwk.exp = Math.floor(expiresAt.getTime() / 1000);
      }

      // Generate X.509 certificate data if we have certificate data
      // Note: This only works if you pass actual X.509 certificates, not just public keys
      const shouldIncludeCertificateData = pem.includes('BEGIN CERTIFICATE'); // Auto-detect if it's a certificate

      if (shouldIncludeCertificateData) {
        const certData = this.generateCertificateData(pem);
        if (certData) {
          jwk.x5c = [certData.certificate];
          jwk.x5t = certData.thumbprint;
          jwk['x5t#S256'] = certData.thumbprintSha256;
        }
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
   */
  private generateCertificateData(
    pemCertificate: string,
  ): { certificate: string; thumbprint: string; thumbprintSha256: string } | null {
    try {
      // Validate that this is actually a certificate, not just a public key
      if (!pemCertificate.includes('BEGIN CERTIFICATE')) {
        this.logger.debug('PEM data is not a certificate, skipping X.509 fields');
        return null;
      }

      // Extract the base64 certificate data (remove headers, footers, and whitespace)
      const certBase64 = pemCertificate
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/\s+/g, '');

      // Validate base64 format
      if (!this.isValidBase64(certBase64)) {
        this.logger.warn('Invalid base64 certificate data');
        return null;
      }

      // Convert to DER format (binary)
      const certDer = Buffer.from(certBase64, 'base64');

      // Validate minimum certificate size (typical X.509 certs are at least 200+ bytes)
      if (certDer.length < 100) {
        this.logger.warn('Certificate data appears too small to be valid');
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
      // Base64 uses A-Z, a-z, 0-9, +, / and = for padding
      const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
      return base64Regex.test(str) && str.length > 0;
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

      return this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt);
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
   * Validate JWK structure (useful for testing)
   */
  public validateJwk(jwk: JWK): boolean {
    try {
      // Check required fields
      const requiredFields = ['kty', 'use', 'kid', 'alg', 'n', 'e'] as const;
      for (const field of requiredFields) {
        if (!(field in jwk) || !jwk[field]) {
          this.logger.error(`Missing or empty required field: ${field}`);
          return false;
        }
      }

      // Validate specific values
      if (jwk.kty !== 'RSA') {
        this.logger.error(`Invalid key type: ${jwk.kty}, expected RSA`);
        return false;
      }

      if (jwk.use !== 'sig') {
        this.logger.error(`Invalid use: ${jwk.use}, expected sig`);
        return false;
      }

      // Validate Base64url encoding of n and e
      if (!this.isValidBase64Url(jwk.n) || !this.isValidBase64Url(jwk.e)) {
        this.logger.error('Invalid Base64url encoding for n or e');
        return false;
      }

      return true;
    } catch (error) {
      this.logger.error('Error validating JWK', this.getErrorStack(error));
      return false;
    }
  }

  /**
   * Validate Base64url encoding
   */
  private isValidBase64Url(str: string): boolean {
    try {
      // Base64url uses A-Z, a-z, 0-9, -, _ and no padding
      const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
      return base64UrlRegex.test(str);
    } catch {
      return false;
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
