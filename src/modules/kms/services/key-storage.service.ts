import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';

import { MoreThan, Repository } from 'typeorm';

import { CryptographicKey } from '../entities/cryptographic-key.entity';
import { KeyRotationLog } from '../entities/key-rotation-log.entity';

import { KeyGenerationService, KeyPair } from './key-generation.service';

const scryptAsync = promisify(scrypt);

@Injectable()
export class KeyStorageService implements OnModuleInit {
  private readonly logger = new Logger(KeyStorageService.name);
  private readonly ENCRYPTION_ALGORITHM = 'aes-256-ctr';
  private encryptionKey: Buffer;
  private initializationPromise: Promise<void> | null = null;

  constructor(
    private readonly configService: ConfigService,
    private readonly keyGenerationService: KeyGenerationService,
    @InjectRepository(CryptographicKey)
    private readonly keyRepository: Repository<CryptographicKey>,
    @InjectRepository(KeyRotationLog)
    private readonly rotationLogRepository: Repository<KeyRotationLog>,
  ) {}

  async onModuleInit() {
    await this.initializeEncryption();
    // Use singleton pattern to prevent race condition on concurrent initialization
    if (!this.initializationPromise) {
      this.initializationPromise = this.ensureActiveKey();
    }
    await this.initializationPromise;
  }

  /**
   * Ensure at least one active key exists in DB
   * Uses database-level atomic operations to prevent race conditions
   */
  private async ensureActiveKey(): Promise<void> {
    try {
      // Use a database transaction to ensure atomicity and prevent race conditions
      await this.keyRepository.manager.transaction(async (transactionalEntityManager) => {
        // Double-check within transaction to handle race conditions
        const currentKey = await transactionalEntityManager
          .createQueryBuilder(CryptographicKey, 'key')
          .where('key.is_active = :isActive AND key.expires_at > :now', {
            isActive: true,
            now: new Date(),
          })
          .setLock('pessimistic_write') // Lock to prevent concurrent modifications
          .getOne();

        if (!currentKey) {
          this.logger.log('No active keys found. Generating initial key...');

          // Generate and store a new key within the transaction
          const keyPair = await this.keyGenerationService.generateKeyPair();
          
          const encryptedPrivateKey = this.encrypt(keyPair.privateKey);
          const key = transactionalEntityManager.create(CryptographicKey, {
            kid: keyPair.kid,
            publicKey: keyPair.publicKey,
            privateKey: encryptedPrivateKey,
            algorithm: keyPair.algorithm,
            expiresAt: keyPair.expiresAt,
            isActive: true,
          });

          await transactionalEntityManager.save(key);

          // Log initial key creation
          await this.logKeyRotation({
            oldKid: null,
            newKid: keyPair.kid,
            rotationType: 'initial',
            reason: 'Initial key generation on startup',
            rotatedBy: 'system-init',
          });

          this.logger.log(`Initial key generated with kid: ${keyPair.kid}`);
        } else {
          this.logger.log(`Found existing active key: ${currentKey.kid}`);
        }
      });
    } catch (error) {
      this.logger.error(
        'Failed to ensure active key during initialization',
        this.getErrorStack(error),
      );
      throw new Error('Critical: Failed to initialize KMS with active keys');
    }
  }

  /**
   * Helper method to safely extract error stack trace
   */
  private getErrorStack(error: unknown): string {
    if (error instanceof Error) {
      return error.stack || error.message || 'Unknown error';
    }
    return String(error);
  }

  /**
   * Get all active cryptographic keys (non-expired only)
   * @returns Array of active, non-expired cryptographic keys
   */
  async getActiveKeys() {
    try {
      const now = new Date();
      return await this.keyRepository.find({
        where: {
          isActive: true,
          expiresAt: MoreThan(now),
        },
        order: {
          createdAt: 'DESC', // Return most recently created keys first
        },
      });
    } catch (error) {
      this.logger.error('Error retrieving active keys', this.getErrorStack(error));
      throw error;
    }
  }

  /**
   * Log a key rotation event
   * @param options The rotation details
   */
  async logKeyRotation(options: {
    oldKid?: string | null;
    newKid: string;
    rotationType: 'initial' | 'scheduled' | 'emergency' | 'manual';
    reason?: string;
    rotatedBy?: string;
  }): Promise<void> {
    try {
      const log = this.rotationLogRepository.create({
        oldKid: options.oldKid || null,
        newKid: options.newKid,
        rotationType: options.rotationType,
        rotationReason: options.reason || null,
        rotatedBy: options.rotatedBy || 'system',
      });

      await this.rotationLogRepository.save(log);
      this.logger.log(`Logged key rotation from ${options.oldKid || 'N/A'} to ${options.newKid}`);
    } catch (error) {
      this.logger.error('Failed to log key rotation', this.getErrorStack(error));
      // Don't throw here as logging failure shouldn't break key operations
    }
  }

  private async initializeEncryption(): Promise<void> {
    try {
      const encryptionKey = this.configService.get<string>('KMS_ENCRYPTION_KEY');

      if (!encryptionKey) {
        // ONLY for fresh DB/dev/testing; warns in prod
        this.logger.warn(
          'No KMS_ENCRYPTION_KEY found in environment. Using in-memory key (NOT for production)',
        );
        this.encryptionKey = randomBytes(32);
      } else {
        // Derive a 32-byte key from passphrase
        this.encryptionKey = (await scryptAsync(encryptionKey, 'salt', 32)) as Buffer;
      }
    } catch (error) {
      this.logger.error('Failed to initialize encryption', this.getErrorStack(error));
      throw new Error('Failed to initialize encryption');
    }
  }

  private encrypt(data: string): string {
    try {
      const iv = randomBytes(16);
      const cipher = createCipheriv(this.ENCRYPTION_ALGORITHM, this.encryptionKey, iv);
      const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
      return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
    } catch (error) {
      this.logger.error('Failed to encrypt data', this.getErrorStack(error));
      throw new Error('Encryption failed');
    }
  }

  private decrypt(encryptedData: string): string {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    try {
      const [ivHex, encryptedText] = encryptedData.split(':');
      if (!ivHex || !encryptedText) {
        throw new Error('Invalid encrypted data format');
      }

      const iv = Buffer.from(ivHex, 'hex');
      const encryptedTextBuffer = Buffer.from(encryptedText, 'hex');
      const decipher = createDecipheriv(this.ENCRYPTION_ALGORITHM, this.encryptionKey, iv);
      return Buffer.concat([decipher.update(encryptedTextBuffer), decipher.final()]).toString(
        'utf8',
      );
    } catch (error) {
      this.logger.error('Failed to decrypt data', this.getErrorStack(error));
      throw new Error('Decryption failed');
    }
  }

  public async storeKey(keyPair: KeyPair): Promise<void> {
    try {
      const encryptedPrivateKey = this.encrypt(keyPair.privateKey);

      const key = this.keyRepository.create({
        kid: keyPair.kid,
        publicKey: keyPair.publicKey,
        privateKey: encryptedPrivateKey,
        algorithm: keyPair.algorithm,
        expiresAt: keyPair.expiresAt,
        isActive: true,
      });

      await this.keyRepository.save(key);
      this.logger.log(
        `Stored new key with kid: ${keyPair.kid}, expires: ${keyPair.expiresAt.toISOString()}`,
      );
    } catch (error) {
      this.logger.error(`Error storing key ${keyPair.kid}:`, this.getErrorStack(error));
      throw new Error(`Failed to store key: ${keyPair.kid}`);
    }
  }

  async deactivateKey(kid: string, reason: string): Promise<void> {
    try {
      const result = await this.keyRepository.update(
        { kid },
        { isActive: false, rotationReason: reason },
      );

      if (result.affected === 0) {
        this.logger.warn(`No key found to deactivate with kid: ${kid}`);
      } else {
        this.logger.log(`Deactivated key with kid: ${kid}, reason: ${reason}`);
      }
    } catch (error) {
      this.logger.error(`Error deactivating key ${kid}:`, this.getErrorStack(error));
      throw new Error(`Failed to deactivate key: ${kid}`);
    }
  }

  public async getKey(kid: string): Promise<KeyPair | undefined> {
    try {
      const entity = await this.keyRepository.findOne({ where: { kid } });
      if (!entity) return undefined;

      return {
        kid: entity.kid,
        algorithm: entity.algorithm as 'RS256',
        publicKey: entity.publicKey,
        privateKey: this.decrypt(entity.privateKey),
        createdAt: entity.createdAt,
        expiresAt: entity.expiresAt,
      };
    } catch (error) {
      this.logger.error(`Error retrieving key ${kid}:`, this.getErrorStack(error));
      return undefined;
    }
  }

  public async getCurrentKey(): Promise<KeyPair | undefined> {
    try {
      const entity = await this.keyRepository
        .createQueryBuilder('key')
        .where('key.is_active = :isActive AND key.expires_at > :now', {
          isActive: true,
          now: new Date(),
        })
        .orderBy('key.created_at', 'DESC')
        .getOne();

      if (!entity) return undefined;

      return {
        kid: entity.kid,
        algorithm: entity.algorithm as 'RS256',
        publicKey: entity.publicKey,
        privateKey: this.decrypt(entity.privateKey),
        createdAt: entity.createdAt,
        expiresAt: entity.expiresAt,
      };
    } catch (error) {
      this.logger.error('Error retrieving current key:', this.getErrorStack(error));
      return undefined;
    }
  }

  public async getAllKeys(): Promise<KeyPair[]> {
    try {
      const entities = await this.keyRepository
        .createQueryBuilder('key')
        .where('key.is_active = :isActive', { isActive: true })
        .orderBy('key.created_at', 'DESC')
        .getMany();

      return entities.map((entity) => ({
        kid: entity.kid,
        algorithm: entity.algorithm as 'RS256',
        publicKey: entity.publicKey,
        privateKey: this.decrypt(entity.privateKey),
        createdAt: entity.createdAt,
        expiresAt: entity.expiresAt,
      }));
    } catch (error) {
      this.logger.error('Error retrieving all keys:', this.getErrorStack(error));
      return [];
    }
  }

  public async removeKey(kid: string): Promise<boolean> {
    try {
      const result = await this.keyRepository.delete({ kid });
      if (result.affected && result.affected > 0) {
        this.logger.log(`Removed key with ID: ${kid}`);
        return true;
      }
      this.logger.warn(`No key found to remove with ID: ${kid}`);
      return false;
    } catch (error) {
      this.logger.error(`Error removing key ${kid}:`, this.getErrorStack(error));
      throw new Error(`Failed to remove key: ${kid}`);
    }
  }

  /**
   * Counts the number of active, non-expired cryptographic keys in the database
   * @returns The number of active keys
   */
  public async countActiveKeys(): Promise<number> {
    try {
      const now = new Date();
      const count = await this.keyRepository
        .createQueryBuilder('key')
        .where('key.isActive = :isActive', { isActive: true })
        .andWhere('key.expiresAt > :now', { now })
        .getCount();
      return count;
    } catch (error) {
      this.logger.error('Failed to count active keys', this.getErrorStack(error));
      throw error;
    }
  }

  /**
   * Get key health information
   * @returns Key health status including counts and expiry info
   */
  public async getKeyHealth(): Promise<{
    activeKeys: number;
    expiredKeys: number;
    nextExpiry?: Date;
    oldestKey?: Date;
  }> {
    try {
      const now = new Date();

      const [activeKeys, expiredKeys] = await Promise.all([
        this.keyRepository.countBy({ isActive: true, expiresAt: MoreThan(now) }),
        this.keyRepository.countBy({ isActive: true, expiresAt: MoreThan(now) }),
      ]);

      const nextExpiringKey = await this.keyRepository
        .createQueryBuilder('key')
        .where('key.isActive = :isActive AND key.expiresAt > :now', {
          isActive: true,
          now,
        })
        .orderBy('key.expiresAt', 'ASC')
        .getOne();

      const oldestKey = await this.keyRepository
        .createQueryBuilder('key')
        .where('key.isActive = :isActive', { isActive: true })
        .orderBy('key.createdAt', 'ASC')
        .getOne();

      return {
        activeKeys,
        expiredKeys,
        nextExpiry: nextExpiringKey?.expiresAt,
        oldestKey: oldestKey?.createdAt,
      };
    } catch (error) {
      this.logger.error('Failed to get key health information', this.getErrorStack(error));
      return { activeKeys: 0, expiredKeys: 0 };
    }
  }
}
