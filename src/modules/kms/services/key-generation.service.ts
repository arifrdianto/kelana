import { createPublicKey, generateKeyPair, generateKeyPairSync, RSAKeyPairOptions } from 'crypto';
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
  keySize?: number;
  publicExponent?: number;
}

@Injectable()
export class KeyGenerationService {
  private readonly logger = new Logger(KeyGenerationService.name);
  private readonly KEY_ALGORITHM = 'rsa';
  private readonly SUPPORTED_KEY_SIZES = [2048, 3072, 4096];
  private readonly RECOMMENDED_EXPONENTS = [65537, 17, 3];

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
      const publicExponent = this.getPublicExponent();

      expiresAt.setDate(now.getDate() + expiryDays);

      const passphrase = this.configService.get<string>('KMS_KEY_PASSPHRASE');

      // Generate key pair with conditional encryption
      const keyPairOptions: RSAKeyPairOptions<'pem', 'pem'> = {
        modulusLength: keySize,
        publicExponent,
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

      this.validateGeneratedKey(publicKey, keySize, publicExponent);

      const kid = this.generateKeyId();

      this.logger.log(
        `Generated new ${keySize}-bit RSA key pair with kid: ${kid}, expires: ${expiresAt.toISOString()}, exponent: ${publicExponent}`,
      );

      return {
        privateKey: privateKey,
        publicKey: publicKey,
        kid,
        algorithm: 'RS256',
        createdAt: now,
        expiresAt,
        keySize,
        publicExponent,
      };
    } catch (error) {
      this.logger.error('Error generating key pair', error instanceof Error ? error.stack : error);
      throw new Error(
        `Failed to generate key pair: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  /**
   * Validate generated key meets security requirements
   */
  private validateGeneratedKey(
    publicKeyPem: string,
    expectedKeySize: number,
    expectedExponent: number,
  ): void {
    try {
      // Create KeyObject to extract key details
      const publicKeyObj = createPublicKey(publicKeyPem);

      if (publicKeyObj.asymmetricKeyType !== 'rsa') {
        throw new Error(`Generated key is not RSA: ${publicKeyObj.asymmetricKeyType}`);
      }

      // Export as JWK to get n and e values for validation
      const jwk = publicKeyObj.export({ format: 'jwk' }) as {
        kty?: string;
        n?: string;
        e?: string;
      };

      if (!jwk.n || !jwk.e) {
        throw new Error('Failed to extract RSA parameters from generated key');
      }

      // Validate key size
      const nBuffer = Buffer.from(jwk.n.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      const actualKeySize = nBuffer.length * 8;

      if (actualKeySize !== expectedKeySize) {
        throw new Error(
          `Generated key size mismatch: expected ${expectedKeySize}, got ${actualKeySize}`,
        );
      }

      // Validate public exponent
      const eBuffer = Buffer.from(jwk.e.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      const actualExponent = eBuffer.readUIntBE(0, eBuffer.length);

      if (actualExponent !== expectedExponent) {
        throw new Error(
          `Generated exponent mismatch: expected ${expectedExponent}, got ${actualExponent}`,
        );
      }

      // Additional security checks
      this.performSecurityValidation(nBuffer, actualExponent);

      this.logger.debug(
        `Key validation passed: ${actualKeySize} bits, exponent: ${actualExponent}`,
      );
    } catch (error) {
      this.logger.error('Generated key validation failed', error);
      throw new Error(
        `Key validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  /**
   * Perform additional security validation on generated key
   */
  private performSecurityValidation(modulus: Buffer, exponent: number): void {
    // Check for obvious patterns or weaknesses in modulus
    const leadingZeros = modulus.findIndex((byte) => byte !== 0);
    if (leadingZeros > 2) {
      this.logger.warn(`Generated key has ${leadingZeros} leading zero bytes in modulus`);
    }

    // Ensure modulus is odd (required for RSA)
    if ((modulus[modulus.length - 1] & 1) === 0) {
      throw new Error('Generated RSA modulus is even (invalid)');
    }

    // Validate exponent is appropriate
    if (exponent < 3) {
      throw new Error(`Public exponent ${exponent} is too small (minimum 3)`);
    }

    if (exponent % 2 === 0) {
      throw new Error(`Public exponent ${exponent} must be odd`);
    }

    // Check for entropy in high-order bits
    const highOrderByte = modulus[leadingZeros || 0];
    if (highOrderByte < 0x80) {
      this.logger.warn('Generated key may have insufficient entropy in high-order bits');
    }

    this.logger.debug('Security validation passed for generated key');
  }

  /**
   * Generate a unique key ID (kid) compliant with RFC 7517.
   * Combines high-entropy randomness with instance-specific identifier.
   */
  private generateKeyId(): string {
    const randomPart = randomBytes(12).toString('hex'); // ~96 bits entropy
    const machineId = this.getMachineIdentifier();

    return `kid_${randomPart}_${machineId}`;
  }

  /**
   * Get a stable machine/instance identifier.
   * Falls back to process.pid if no config vars are set,
   * ensuring uniqueness across parallel instances.
   */
  private getMachineIdentifier(): string {
    const instanceId =
      this.configService.get<string>('NODE_APP_INSTANCE') ||
      this.configService.get<string>('HOSTNAME') ||
      process.pid.toString();

    return instanceId
      .slice(0, 8)
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
  }

  /**
   * Enhanced key size configuration with validation
   */
  private getKeySize(): number {
    const configuredSize = parseInt(this.configService.get<string>('KMS_KEY_SIZE', '2048'), 10);

    // Validate against supported sizes
    if (!this.SUPPORTED_KEY_SIZES.includes(configuredSize)) {
      this.logger.warn(
        `Configured key size ${configuredSize} not in supported list [${this.SUPPORTED_KEY_SIZES.join(
          ', ',
        )}]. Using 2048.`,
      );
      return 2048;
    }

    // Security recommendations
    if (configuredSize < 2048) {
      this.logger.error(
        `Key size ${configuredSize} is below minimum security requirement of 2048 bits`,
      );
      throw new Error('Key size below minimum security requirement');
    }

    if (configuredSize > 4096) {
      this.logger.warn(`Key size ${configuredSize} is very large and may impact performance`);
    }

    return configuredSize;
  }

  /**
   * Get configured public exponent with security validation
   */
  private getPublicExponent(): number {
    const configuredExponent = parseInt(
      this.configService.get<string>('KMS_PUBLIC_EXPONENT', '65537'),
      10,
    );

    // Validate exponent
    if (!this.RECOMMENDED_EXPONENTS.includes(configuredExponent)) {
      this.logger.warn(
        `Public exponent ${configuredExponent} not in recommended list [${this.RECOMMENDED_EXPONENTS.join(
          ', ',
        )}]. Consider using 65537.`,
      );
    }

    if (configuredExponent < 3) {
      throw new Error('Public exponent must be at least 3');
    }

    if (configuredExponent % 2 === 0) {
      throw new Error('Public exponent must be odd');
    }

    // Warn about potentially weak exponents
    if (configuredExponent === 3) {
      this.logger.warn('Using public exponent 3 may have security implications for some use cases');
    }

    return configuredExponent;
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
   * Enhanced validation with security checks
   */
  validateKeyPair(keyPair: KeyPair): boolean {
    try {
      // Basic structural validation
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

      // Validate key size if available
      if (keyPair.keySize && keyPair.keySize < 2048) {
        this.logger.error(`Key size ${keyPair.keySize} below minimum requirement`);
        return false;
      }

      // Validate public exponent if available
      if (keyPair.publicExponent && keyPair.publicExponent % 2 === 0) {
        this.logger.error('Public exponent must be odd');
        return false;
      }

      // Perform cryptographic validation
      return this.validateKeyStrength(keyPair.publicKey);
    } catch (error) {
      this.logger.error('Error validating key pair', error);
      return false;
    }
  }

  /**
   * Validate cryptographic strength of public key
   */
  private validateKeyStrength(publicKeyPem: string): boolean {
    try {
      const publicKeyObj = createPublicKey(publicKeyPem);

      if (publicKeyObj.asymmetricKeyType !== 'rsa') {
        this.logger.error('Key is not RSA type');
        return false;
      }

      return true;
    } catch (error) {
      this.logger.error('Error validating key strength', error);
      return false;
    }
  }
}
