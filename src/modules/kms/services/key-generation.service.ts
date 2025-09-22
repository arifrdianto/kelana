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
  algorithm: string;
  createdAt: Date;
  expiresAt: Date;
}

@Injectable()
export class KeyGenerationService {
  private readonly logger = new Logger(KeyGenerationService.name);
  private readonly KEY_ALGORITHM = 'rsa'; // Use 'rsa' instead of 'RSA-PSS' for better compatibility

  constructor(private readonly configService: ConfigService) {}

  /**
   * Generate a new RSA key pair with configurable options
   * @returns Promise<KeyPair>
   */
  async generateKeyPair(): Promise<KeyPair> {
    try {
      const now = new Date();
      const expiresAt = new Date(now);

      const keySize = this.getKeySize();
      const expiryDays = this.getKeyExpiryDays();

      expiresAt.setDate(now.getDate() + expiryDays);

      const passphrase = this.configService.get<string>('KMS_KEY_PASSPHRASE');

      // Generate key pair with conditional encryption
      const keyPairOptions: RSAKeyPairOptions<'pem', 'pem'> = {
        modulusLength: keySize,
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

      this.logger.log(
        `Generated new ${keySize}-bit RSA key pair with kid: ${kid}, expires: ${expiresAt.toISOString()}`,
      );

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
   * Generate a unique key ID using crypto-secure random bytes with timestamp
   * @returns string
   */
  private generateKeyId(): string {
    const timestamp = Date.now().toString(36);
    const randomPart = randomBytes(8).toString('hex'); // Increased randomness
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

      const keySize = this.getKeySize();
      const expiryDays = this.getKeyExpiryDays();

      expiresAt.setDate(now.getDate() + expiryDays);

      const passphrase = this.configService.get<string>('KMS_KEY_PASSPHRASE');

      // Generate key pair with conditional encryption
      const keyPairOptions: RSAKeyPairOptions<'pem', 'pem'> = {
        modulusLength: keySize,
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

  /**
   * Get configured key size with validation
   */
  private getKeySize(): number {
    const keySize = parseInt(this.configService.get<string>('KMS_KEY_SIZE', '2048'), 10);

    // Validate key size (must be at least 2048 for security)
    if (keySize < 2048) {
      this.logger.warn(
        `Key size ${keySize} is below minimum recommended size of 2048. Using 2048.`,
      );
      return 2048;
    }

    // Common valid RSA key sizes
    const validSizes = [2048, 3072, 4096];
    if (!validSizes.includes(keySize)) {
      this.logger.warn(`Unusual key size ${keySize}. Recommended sizes: ${validSizes.join(', ')}`);
    }

    return keySize;
  }

  /**
   * Get configured key expiry days with validation
   */
  private getKeyExpiryDays(): number {
    const expiryDays = parseInt(this.configService.get<string>('KMS_KEY_EXPIRY_DAYS', '30'), 10);

    // Validate expiry days (minimum 7 days, maximum 365 days)
    if (expiryDays < 7) {
      this.logger.warn(`Key expiry ${expiryDays} days is too short. Using minimum of 7 days.`);
      return 7;
    }

    if (expiryDays > 365) {
      this.logger.warn(
        `Key expiry ${expiryDays} days is very long. Consider shorter rotation periods for better security.`,
      );
    }

    return expiryDays;
  }

  /**
   * Validate key pair format and structure
   * @param keyPair KeyPair to validate
   * @returns boolean indicating if the key pair is structurally valid
   */
  validateKeyPair(keyPair: KeyPair): boolean {
    try {
      // Check required fields
      if (!keyPair.kid || !keyPair.publicKey || !keyPair.privateKey) {
        this.logger.error('Key pair missing required fields');
        return false;
      }

      // Validate PEM format
      if (
        !keyPair.publicKey.includes('-----BEGIN PUBLIC KEY-----') ||
        !keyPair.publicKey.includes('-----END PUBLIC KEY-----')
      ) {
        this.logger.error('Invalid public key PEM format');
        return false;
      }

      if (
        !keyPair.privateKey.includes('-----BEGIN PRIVATE KEY-----') &&
        !keyPair.privateKey.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')
      ) {
        this.logger.error('Invalid private key PEM format');
        return false;
      }

      // Validate algorithm
      if (keyPair.algorithm !== 'RS256') {
        this.logger.error(`Unsupported algorithm: ${keyPair.algorithm}`);
        return false;
      }

      // Validate dates
      if (keyPair.expiresAt <= keyPair.createdAt) {
        this.logger.error('Key expiry date must be after creation date');
        return false;
      }

      return true;
    } catch (error) {
      this.logger.error('Error validating key pair', error);
      return false;
    }
  }
}
