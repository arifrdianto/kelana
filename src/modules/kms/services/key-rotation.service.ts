import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';

import { CronJob } from 'cron';

import { KeyGenerationService, KeyPair } from './key-generation.service';
import { KeyStorageService } from './key-storage.service';

@Injectable()
export class KeyRotationService implements OnModuleInit {
  private readonly logger = new Logger(KeyRotationService.name);
  private readonly ROTATION_CRON = '0 3 * * *'; // Daily at 3 AM
  private readonly KEY_PRE_ROTATION_DAYS = 7; // Start rotating keys 7 days before expiration

  constructor(
    private readonly schedulerRegistry: SchedulerRegistry,
    private readonly keyGenerationService: KeyGenerationService,
    private readonly keyStorageService: KeyStorageService,
  ) {}

  onModuleInit() {
    this.scheduleKeyRotation();
  }

  /**
   * Schedule the key rotation job
   */
  private scheduleKeyRotation(): void {
    const job = new CronJob(this.ROTATION_CRON, () => {
      this.logger.log('Running scheduled key rotation...');
      this.rotateKeysIfNeeded().catch((error) => {
        this.logger.error('Error during key rotation:', error);
      });
    });

    this.schedulerRegistry.addCronJob('keyRotation', job);
    job.start();

    this.logger.log(`Key rotation scheduled with cron pattern: ${this.ROTATION_CRON}`);
  }

  /**
   * Rotate keys if needed based on expiration
   */
  public async rotateKeysIfNeeded(): Promise<void> {
    try {
      const currentKeys = await this.keyStorageService.getAllKeys();
      const now = new Date();
      let rotationNeeded = false;

      // Check if we need to rotate any keys
      for (const key of currentKeys) {
        const expiryDate = new Date(key.expiresAt);
        const daysUntilExpiry = Math.ceil(
          (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
        );

        if (daysUntilExpiry <= this.KEY_PRE_ROTATION_DAYS) {
          this.logger.log(`Key ${key.kid} will expire in ${daysUntilExpiry} days. Rotating...`);
          rotationNeeded = true;
          break;
        }
      }

      // If no keys need rotation yet, check if we have at least one active key
      if (!rotationNeeded && currentKeys.length === 0) {
        rotationNeeded = true;
        this.logger.log('No active keys found. Generating initial key...');
      }

      if (rotationNeeded) {
        await this.rotateKeys();
      } else {
        this.logger.log('No key rotation needed at this time.');
      }
    } catch (error) {
      this.logger.error('Error during key rotation check', error.stack);
    }
  }

  /**
   * Rotate all keys that need rotation
   */
  public async rotateKeys(): Promise<KeyPair> {
    try {
      // Generate a new key pair
      const newKeyPair = await this.keyGenerationService.generateKeyPair();

      // Get the current active key before deactivating it
      const currentKey = await this.keyStorageService.getCurrentKey();

      // Store the new key
      await this.keyStorageService.storeKey(newKeyPair);

      // Deactivate old key
      if (currentKey) {
        await this.keyStorageService.deactivateKey(currentKey.kid, 'rotated');
      }

      // Log the rotation
      await this.keyStorageService.logKeyRotation({
        oldKid: currentKey?.kid,
        newKid: newKeyPair.kid,
        rotationType: 'scheduled',
        reason: 'Scheduled key rotation',
      });

      // Clean up expired keys
      await this.cleanupExpiredKeys();

      this.logger.log(`Successfully rotated keys. New key ID: ${newKeyPair.kid}`);
      return newKeyPair;
    } catch (error) {
      this.logger.error('Error rotating keys', error.stack);
      throw new Error('Failed to rotate keys');
    }
  }

  /**
   * Clean up expired keys, keeping a configurable number of recent keys
   */
  private async cleanupExpiredKeys(): Promise<void> {
    try {
      const keys = await this.keyStorageService.getAllKeys();

      // Sort keys by expiration date (newest first)
      const sortedKeys = [...keys].sort(
        (a, b) => new Date(b.expiresAt).getTime() - new Date(a.expiresAt).getTime(),
      );

      const keysToRemove = sortedKeys.slice(3);

      // Remove old keys
      for (const key of keysToRemove) {
        await this.keyStorageService.removeKey(key.kid);
        this.logger.log(`Removed expired key: ${key.kid}`);
      }
    } catch (error) {
      this.logger.error('Error cleaning up expired keys', error.stack);
    }
  }
}
