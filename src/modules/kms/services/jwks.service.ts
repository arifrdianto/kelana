import { createHash, createPublicKey } from 'crypto';

import { Injectable, Logger } from '@nestjs/common';

import { InvalidJWKException } from '@/shared/exceptions/jwk.exception';

import { JWK, JWKS, KeyOperation } from '../interfaces/jwk.interface';

import { KeyStorageService } from './key-storage.service';

export interface RsaJwk extends JWK {
  kty: 'RSA';
  use: 'sig';
  alg: 'RS256' | 'RS384' | 'RS512';
  n: string;
  e: string;
  exp?: number; // non-standard, optional
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

      for (const key of keys) {
        try {
          if (this.isKeyExpired(key.expiresAt)) {
            this.logger.debug(`Skipping expired key in JWKS: ${key.kid}`);
            continue;
          }

          const alg = key.alg ?? key.algorithm ?? this.DEFAULT_ALGORITHM;
          const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt, alg);

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
        }
      }

      if (jwks.length === 0) {
        this.logger.warn('No valid keys available for JWKS');
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
  public async getJwk(kid: string): Promise<RsaJwk | null> {
    try {
      const key = (await this.keyStorageService.getKey(kid)) as StoredKey | null;
      if (!key) {
        this.logger.debug(`Key not found: ${kid}`);
        return null;
      }

      if (this.isKeyExpired(key.expiresAt)) {
        this.logger.warn(`Requested key is expired: ${kid}`);
        return null;
      }

      const alg = key.alg ?? key.algorithm ?? this.DEFAULT_ALGORITHM;
      const jwk = this.convertPemToJwk(key.publicKey, key.kid, key.expiresAt, alg);

      if (!this.validateJwk(jwk)) {
        throw new InvalidJWKException([`Generated invalid JWK for key: ${kid}`]);
      }

      return jwk;
    } catch (error) {
      if (error instanceof InvalidJWKException) throw error;

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

      const jwk: RsaJwk = {
        kty: this.KEY_TYPE,
        use: 'sig',
        kid,
        alg,
        n: keyData.n,
        e: keyData.e,
        key_ops: [...this.KEY_OPERATIONS],
      };

      if (expiresAt && !this.isKeyExpired(expiresAt)) {
        jwk.exp = Math.floor(expiresAt.getTime() / 1000);
      }

      const certs = this.extractCertificates(pem);
      if (certs.length > 0) {
        jwk.x5c = certs;
        jwk.x5t = this.generateThumbprint(certs[0], 'sha1');
        jwk['x5t#S256'] = this.generateThumbprint(certs[0], 'sha256');
      }

      return jwk;
    } catch (error) {
      this.logger.error(`Error converting PEM to JWK for kid: ${kid}`, this.getErrorStack(error));
      throw new Error(
        `Failed to convert public key to JWK format: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
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

  public validateJwk(jwk: RsaJwk): boolean {
    const requiredFields: (keyof RsaJwk)[] = ['kty', 'use', 'kid', 'alg', 'n', 'e'];
    for (const field of requiredFields) {
      if (!jwk[field]) {
        this.logger.error(`JWK validation failed: Missing ${field}`);
        return false;
      }
    }

    if (!['RS256', 'RS384', 'RS512'].includes(jwk.alg)) {
      this.logger.error(`JWK validation failed: Unsupported alg: ${jwk.alg}`);
      return false;
    }

    if (!this.isValidBase64Url(jwk.n)) return false;
    if (!this.isValidBase64Url(jwk.e)) return false;

    return this.validateRsaKeyStrength(jwk.n, jwk.e);
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

  private getErrorStack(error: unknown): string {
    return error instanceof Error ? error.stack || error.message : String(error);
  }
}
