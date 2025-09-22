import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';

import { MoreThan, Repository } from 'typeorm';

import { CryptographicKey } from '../entities/cryptographic-key.entity';
import { KeyRotationLog } from '../entities/key-rotation-log.entity';

import { KeyPair } from './key-generation.service';

const scryptAsync = promisify(scrypt);

@Injectable()
export class KeyStorageService implements OnModuleInit {
  private readonly logger = new Logger(KeyStorageService.name);
  private readonly ENCRYPTION_ALGORITHM = 'aes-256-ctr';
  private encryptionKey: Buffer;

  /**
   * Helper method to safely extract error stack trace
   */
  private getErrorStack(error: unknown): string {
    if (error instanceof Error) {
      return error.stack || error.message || 'Unknown error';
    }
    return String(error);
  }

  constructor(
    private readonly configService: ConfigService,
    @InjectRepository(CryptographicKey)
    private readonly keyRepository: Repository<CryptographicKey>,
    @InjectRepository(KeyRotationLog)
    private readonly rotationLogRepository: Repository<KeyRotationLog>,
  ) {}

  async onModuleInit() {
    await this.initializeEncryption();
  }

  /**
   * Get all active cryptographic keys
   * @returns Array of active cryptographic keys
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
          expiresAt: 'DESC', // Return most recently expiring keys first
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
    rotationType: 'scheduled' | 'emergency' | 'manual';
    reason?: string;
    rotatedBy?: string;
  }): Promise<void> {
    const log = this.rotationLogRepository.create({
      oldKid: options.oldKid || null,
      newKid: options.newKid,
      rotationType: options.rotationType,
      rotationReason: options.reason || null,
      rotatedBy: options.rotatedBy || 'system',
    });

    await this.rotationLogRepository.save(log);
    this.logger.log(`Logged key rotation from ${options.oldKid || 'N/A'} to ${options.newKid}`);
  }

  private async initializeEncryption(): Promise<void> {
    try {
      const encryptionKey = this.configService.get<string>('KMS_ENCRYPTION_KEY');
      if (!encryptionKey) {
        this.logger.warn(
          'No KMS_ENCRYPTION_KEY found in environment. Using in-memory key (not recommended for production)',
        );
        this.encryptionKey = randomBytes(32);
      } else {
        this.encryptionKey = (await scryptAsync(encryptionKey, 'salt', 32)) as Buffer;
      }
    } catch (error) {
      this.logger.error('Failed to initialize encryption', error.stack);
      throw new Error('Failed to initialize encryption');
    }
  }

  private encrypt(data: string): string {
    const iv = randomBytes(16);
    const cipher = createCipheriv(this.ENCRYPTION_ALGORITHM, this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
  }

  private decrypt(encryptedData: string): string {
    const [ivHex, encryptedText] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const encryptedTextBuffer = Buffer.from(encryptedText, 'hex');
    const decipher = createDecipheriv(this.ENCRYPTION_ALGORITHM, this.encryptionKey, iv);
    return Buffer.concat([decipher.update(encryptedTextBuffer), decipher.final()]).toString('utf8');
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
      this.logger.log(`Stored new key with kid: ${keyPair.kid}`);
    } catch (error) {
      this.logger.error('Error storing key:', error);
      throw new Error('Failed to store key');
    }
  }

  async deactivateKey(kid: string, reason: string): Promise<void> {
    try {
      await this.keyRepository.update({ kid }, { isActive: false, rotationReason: reason });
      this.logger.log(`Deactivated key with kid: ${kid}`);
    } catch (error) {
      this.logger.error(`Error deactivating key ${kid}:`, error);
      throw new Error(`Failed to deactivate key: ${kid}`);
    }
  }

  public async getKey(kid: string): Promise<KeyPair | undefined> {
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
  }

  public async getCurrentKey(): Promise<KeyPair | undefined> {
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
  }

  public async getAllKeys(): Promise<KeyPair[]> {
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
  }

  public async removeKey(kid: string): Promise<boolean> {
    const result = await this.keyRepository.delete({ kid });
    if (result.affected && result.affected > 0) {
      this.logger.log(`Removed key with ID: ${kid}`);
      return true;
    }
    return false;
  }

  /**
   * Counts the number of active cryptographic keys in the database
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
      const errorMessage = error instanceof Error ? error.stack : 'Unknown error';
      this.logger.error('Failed to count active keys', errorMessage);
      throw error;
    }
  }
}
