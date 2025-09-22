import { generateKeyPair, generateKeyPairSync, RSAKeyPairOptions } from 'crypto';
import { randomBytes } from 'crypto';
import { promisify } from 'util';

import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

const generateKeyPairAsync = promisify(generateKeyPair);

export interface KeyPair {
  privateKey: string;
  publicKey: string;
  kid: string;
  algorithm: 'RS256';
  createdAt: Date;
  expiresAt: Date;
}

@Injectable()
export class KeyGenerationService {
  private readonly logger = new Logger(KeyGenerationService.name);
  private readonly KEY_SIZE = 2048; // RSA key size in bits (2048 is standard, 4096 is overkill for most use cases)
  private readonly KEY_ALGORITHM = 'rsa'; // Use 'rsa' instead of 'RSA-PSS' for better compatibility
  private readonly KEY_EXPIRY_DAYS = 30;

  constructor(private readonly configService: ConfigService) {}

  /**
   * Generate a new RSA key pair
   * @returns Promise<KeyPair>
   */
  async generateKeyPair(): Promise<KeyPair> {
    try {
      const now = new Date();
      const expiresAt = new Date(now);
      expiresAt.setDate(now.getDate() + this.KEY_EXPIRY_DAYS);

      const passphrase = this.configService.get<string>('KMS_KEY_PASSPHRASE');

      // Generate key pair with conditional encryption
      const keyPairOptions: RSAKeyPairOptions<'pem', 'pem'> = {
        modulusLength: this.KEY_SIZE,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      };

      // Only add encryption if passphrase is provided
      if (passphrase) {
        keyPairOptions.privateKeyEncoding.cipher = 'aes-256-cbc';
        keyPairOptions.privateKeyEncoding.passphrase = passphrase;
      }

      const { publicKey, privateKey } = await generateKeyPairAsync(
        this.KEY_ALGORITHM,
        keyPairOptions,
      );

      const kid = this.generateKeyId();

      return {
        privateKey: privateKey,
        publicKey: publicKey,
        kid,
        algorithm: 'RS256',
        createdAt: now,
        expiresAt,
      };
    } catch (error) {
      this.logger.error('Error generating key pair', error instanceof Error ? error.stack : error);
      throw new Error('Failed to generate key pair');
    }
  }

  /**
   * Generate a unique key ID using crypto-secure random bytes
   * @returns string
   */
  private generateKeyId(): string {
    const timestamp = Date.now().toString(36);
    const randomPart = randomBytes(6).toString('hex');
    return `kid_${timestamp}_${randomPart}`;
  }

  /**
   * Generate a new key pair synchronously (for testing purposes)
   * @returns KeyPair
   */
  generateKeyPairSync(): KeyPair {
    try {
      const now = new Date();
      const expiresAt = new Date(now);
      expiresAt.setDate(now.getDate() + this.KEY_EXPIRY_DAYS);

      const passphrase = this.configService.get<string>('KMS_KEY_PASSPHRASE');

      // Generate key pair with conditional encryption
      const keyPairOptions: RSAKeyPairOptions<'pem', 'pem'> = {
        modulusLength: this.KEY_SIZE,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      };

      // Only add encryption if passphrase is provided
      if (passphrase) {
        keyPairOptions.privateKeyEncoding.cipher = 'aes-256-cbc';
        keyPairOptions.privateKeyEncoding.passphrase = passphrase;
      }

      const { publicKey, privateKey } = generateKeyPairSync(this.KEY_ALGORITHM, keyPairOptions);

      return {
        privateKey: privateKey,
        publicKey: publicKey,
        kid: this.generateKeyId(),
        algorithm: 'RS256',
        createdAt: now,
        expiresAt,
      };
    } catch (error) {
      this.logger.error(
        'Error generating key pair synchronously',
        error instanceof Error ? error.stack : error,
      );
      throw new Error('Failed to generate key pair synchronously');
    }
  }

  /**
   * Validate if a key pair is still valid (not expired)
   * @param keyPair KeyPair to validate
   * @returns boolean
   */
  isKeyPairValid(keyPair: KeyPair): boolean {
    return new Date() < keyPair.expiresAt;
  }

  /**
   * Get the number of days until key expiration
   * @param keyPair KeyPair to check
   * @returns number of days (negative if expired)
   */
  getDaysUntilExpiration(keyPair: KeyPair): number {
    const now = new Date();
    const diffTime = keyPair.expiresAt.getTime() - now.getTime();
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }
}
