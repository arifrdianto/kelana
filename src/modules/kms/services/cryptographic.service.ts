import { Injectable, Logger } from '@nestjs/common';

import { decode, JwtPayload, sign, SignOptions, verify, VerifyOptions } from 'jsonwebtoken';

import { KeyStorageService } from './key-storage.service';

export interface JwtSignOptions extends Omit<SignOptions, 'algorithm' | 'keyid'> {
  expiresIn?: SignOptions['expiresIn'];
  notBefore?: SignOptions['notBefore'];
  audience?: SignOptions['audience'];
  issuer?: SignOptions['issuer'];
  subject?: SignOptions['subject'];
  noTimestamp?: SignOptions['noTimestamp'];
  header?: SignOptions['header'];
}

export interface JwtVerifyOptions extends Omit<VerifyOptions, 'algorithms' | 'complete'> {
  ignoreExpiration?: boolean;
  ignoreNotBefore?: boolean;
  clockTolerance?: number;
}

@Injectable()
export class CryptographicService {
  private readonly logger = new Logger(CryptographicService.name);
  private readonly DEFAULT_ALGORITHM = 'RS256';
  private readonly DEFAULT_EXPIRES_IN = '1h';

  constructor(private readonly keyStorageService: KeyStorageService) {}

  /**
   * Sign a JWT payload with the current active key
   */
  public async sign<T extends object>(payload: T, options: JwtSignOptions = {}): Promise<string> {
    try {
      const key = await this.keyStorageService.getCurrentKey();

      if (!key) {
        throw new Error('No active key available for signing');
      }

      if (!key.privateKey) {
        throw new Error('Private key is not available for signing');
      }

      // Ensure we have all required properties before signing
      if (!key.kid) {
        throw new Error('Key ID (kid) is required for JWT signing');
      }

      // Create sign options with explicit typing
      const signOptions: SignOptions = {
        algorithm: this.DEFAULT_ALGORITHM as 'RS256',
        keyid: key.kid,
        expiresIn: this.DEFAULT_EXPIRES_IN,
        ...options,
      };

      // Use Promise wrapper for sign function
      const result = await new Promise<string>((resolve, reject) => {
        sign(payload, key.privateKey, signOptions, (error, token) => {
          if (error || !token) {
            reject(error || new Error('Failed to generate JWT token'));
          } else {
            resolve(token);
          }
        });
      });

      return result;
    } catch (error: unknown) {
      this.logger.error('Error signing JWT', this.getErrorStack(error));
      throw new Error('Failed to sign JWT');
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
      // Decode without verification to get the key ID
      const decoded = decode(token, { complete: true });

      if (!decoded || typeof decoded === 'string' || !decoded.header) {
        throw new Error('Invalid JWT token');
      }

      const { kid } = decoded.header;
      if (!kid) {
        throw new Error('JWT does not contain a key ID (kid)');
      }

      // Get the key by ID
      const key = await this.keyStorageService.getKey(kid);
      if (!key) {
        throw new Error(`No key found with ID: ${kid}`);
      }

      if (!key.publicKey) {
        throw new Error(`Public key not available for key ID: ${kid}`);
      }

      const verifyOptions: VerifyOptions = {
        algorithms: [this.DEFAULT_ALGORITHM],
        ...options,
      };

      // Use Promise wrapper for verify function
      const verified = await new Promise<T & JwtPayload>((resolve, reject) => {
        verify(token, key.publicKey, verifyOptions, (error, decoded) => {
          if (error) {
            reject(error);
          } else if (!decoded || typeof decoded === 'string') {
            reject(new Error('Invalid token payload'));
          } else {
            resolve(decoded as T & JwtPayload);
          }
        });
      });

      return verified;
    } catch (error) {
      this.logger.error('Error verifying JWT', this.getErrorStack(error));
      throw new Error('Failed to verify JWT');
    }
  }

  /**
   * Decode a JWT token without verification
   */
  public decode<T = any>(token: string): (T & JwtPayload) | null {
    try {
      return decode(token) as (T & JwtPayload) | null;
    } catch (error) {
      this.logger.error('Error decoding JWT', this.getErrorStack(error));
      return null;
    }
  }

  /**
   * Get the public key for a specific key ID
   */
  public async getPublicKey(kid: string): Promise<string | undefined> {
    try {
      const key = await this.keyStorageService.getKey(kid);
      return key?.publicKey;
    } catch (error) {
      this.logger.error(`Error getting public key for kid: ${kid}`, this.getErrorStack(error));
      return undefined;
    }
  }

  /**
   * Get the current active public key
   */
  public async getCurrentPublicKey(): Promise<string | undefined> {
    try {
      const key = await this.keyStorageService.getCurrentKey();
      return key?.publicKey;
    } catch (error) {
      this.logger.error('Error getting current public key', this.getErrorStack(error));
      return undefined;
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
