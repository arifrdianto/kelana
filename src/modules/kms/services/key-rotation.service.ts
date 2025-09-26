import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';

import { CronJob } from 'cron';

import { KeyRotationException } from '@/shared/exceptions/jwk.exception';

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

  async onModuleInit() {
    // Ensure we have at least one key before scheduling rotation
    await this.ensureInitialKey();
    this.scheduleKeyRotation();
  }

  /**
   * Ensure we have at least one active key during rotation service initialization
   */
  private async ensureInitialKey(): Promise<void> {
    try {
      const keyCount = await this.keyStorageService.countActiveKeys();

      if (keyCount === 0) {
        this.logger.log(
          'No active keys found during rotation service init. Generating initial key...',
        );
        await this.rotateKeys();
      } else {
        this.logger.log(`Rotation service initialized with ${keyCount} active key(s)`);
      }
    } catch (error) {
      this.logger.error(
        'Failed to ensure initial key in rotation service',
        this.getErrorStack(error),
      );
    }
  }

  /**
   * Schedule the key rotation job
   */
  private scheduleKeyRotation(): void {
    try {
      const job = new CronJob(this.ROTATION_CRON, () => {
        this.logger.log('Running scheduled key rotation check...');
        this.rotateKeysIfNeeded().catch((error) => {
          this.logger.error('Error during scheduled key rotation:', this.getErrorStack(error));
        });
      });

      this.schedulerRegistry.addCronJob('keyRotation', job);
      job.start();

      this.logger.log(`Key rotation scheduled with cron pattern: ${this.ROTATION_CRON}`);
    } catch (error) {
      this.logger.error('Failed to schedule key rotation', this.getErrorStack(error));
      throw new Error('Failed to schedule key rotation');
    }
  }

  /**
   * Rotate keys if needed based on expiration
   */
  public async rotateKeysIfNeeded(): Promise<void> {
    try {
      const currentKeys = await this.keyStorageService.getActiveKeys();
      const now = new Date();
      let rotationNeeded = false;
      let rotationReason = '';

      // Check if we need to rotate any keys
      for (const key of currentKeys) {
        const expiryDate = new Date(key.expiresAt);
        const daysUntilExpiry = Math.ceil(
          (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
        );

        if (daysUntilExpiry <= this.KEY_PRE_ROTATION_DAYS) {
          this.logger.log(
            `Key ${key.kid} will expire in ${daysUntilExpiry} days. Rotation needed.`,
          );
          rotationNeeded = true;
          rotationReason = `Key expiring in ${daysUntilExpiry} days`;
          break;
        }
      }

      if (!rotationNeeded && currentKeys.length === 0) {
        rotationNeeded = true;
        rotationReason = 'No active keys found';
        this.logger.log('No active keys found. Generating initial key...');
      }

      if (rotationNeeded) {
        this.logger.log(`Key rotation triggered: ${rotationReason}`);
        await this.rotateKeys();
      } else {
        this.logger.debug('No key rotation needed at this time.');
      }
    } catch (error) {
      // CHANGE: Use specific exception type
      const rotationError = new KeyRotationException(
        'Key rotation check failed',
        error instanceof Error ? error : new Error(String(error)),
      );
      this.logger.error('Error during key rotation check', this.getErrorStack(rotationError));
      throw rotationError;
    }
  }

  /**
   * Rotate all keys that need rotation
   */
  public async rotateKeys(): Promise<KeyPair> {
    try {
      this.logger.log('Starting key rotation process...');

      const newKeyPair = await this.keyGenerationService.generateKeyPair();
      this.logger.log(`Generated new key pair with kid: ${newKeyPair.kid}`);

      const currentKey = await this.keyStorageService.getCurrentKey();

      await this.keyStorageService.storeKey(newKeyPair);
      this.logger.log(`Stored new key with kid: ${newKeyPair.kid}`);

      if (currentKey) {
        await this.keyStorageService.deactivateKey(currentKey.kid, 'rotated');
        this.logger.log(`Deactivated old key with kid: ${currentKey.kid}`);
      }

      await this.keyStorageService.logKeyRotation({
        oldKid: currentKey?.kid,
        newKid: newKeyPair.kid,
        rotationType: 'scheduled',
        reason: 'Scheduled key rotation',
        rotatedBy: 'system',
      });

      await this.cleanupExpiredKeys();

      this.logger.log(`Successfully completed key rotation. New active key ID: ${newKeyPair.kid}`);
      return newKeyPair;
    } catch (error) {
      // CHANGE: Use specific exception type
      const rotationError = new KeyRotationException(
        'Key rotation process failed',
        error instanceof Error ? error : new Error(String(error)),
      );
      this.logger.error('Error during key rotation', this.getErrorStack(rotationError));
      throw rotationError;
    }
  }

  /**
   * Clean up expired keys, keeping a configurable number of recent keys for audit purposes
   */
  private async cleanupExpiredKeys(): Promise<void> {
    try {
      const keys = await this.keyStorageService.getAllKeys();

      // Sort keys by creation date (newest first)
      const sortedKeys = [...keys].sort(
        (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );

      // Keep the 3 most recent keys, remove others
      const keysToRemove = sortedKeys.slice(3);
      let removedCount = 0;

      for (const key of keysToRemove) {
        const success = await this.keyStorageService.removeKey(key.kid);
        if (success) {
          removedCount++;
          this.logger.log(`Cleaned up old key: ${key.kid}`);
        }
      }

      if (removedCount > 0) {
        this.logger.log(`Cleanup completed: removed ${removedCount} old key(s)`);
      }
    } catch (error) {
      this.logger.error('Error cleaning up expired keys', this.getErrorStack(error));
      // Don't throw here as cleanup failure shouldn't break rotation
    }
  }

  /**
   * Get rotation statistics for monitoring
   */
  public async getRotationStats(): Promise<{
    totalRotations: number;
    scheduledRotations: number;
    emergencyRotations: number;
    manualRotations: number;
    lastRotation?: Date;
    nextScheduledCheck: Date;
  }> {
    try {
      // This would require additional repository methods to get rotation logs
      // For now, return basic info
      const currentKey = await this.keyStorageService.getCurrentKey();
      const nextCheck = this.getNextScheduledCheck();

      return {
        totalRotations: 0, // Would need to query rotation logs
        scheduledRotations: 0,
        emergencyRotations: 0,
        manualRotations: 0,
        lastRotation: currentKey?.createdAt,
        nextScheduledCheck: nextCheck,
      };
    } catch (error) {
      this.logger.error('Error getting rotation statistics', this.getErrorStack(error));
      return {
        totalRotations: 0,
        scheduledRotations: 0,
        emergencyRotations: 0,
        manualRotations: 0,
        nextScheduledCheck: this.getNextScheduledCheck(),
      };
    }
  }

  /**
   * Calculate the next scheduled rotation check time
   */
  private getNextScheduledCheck(): Date {
    try {
      const job = this.schedulerRegistry.getCronJob('keyRotation');
      return job.nextDate().toJSDate();
    } catch {
      // Fallback: calculate next 3 AM
      const now = new Date();
      const tomorrow = new Date(now);
      tomorrow.setDate(now.getDate() + 1);
      tomorrow.setHours(3, 0, 0, 0);
      return tomorrow;
    }
  }

  /**
   * Stop the key rotation scheduler (useful for graceful shutdown)
   */
  public async stopRotationScheduler(): Promise<void> {
    try {
      const job = this.schedulerRegistry.getCronJob('keyRotation');
      await job.stop();
      this.logger.log('Key rotation scheduler stopped');
    } catch (error) {
      this.logger.warn('Failed to stop key rotation scheduler', this.getErrorStack(error));
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
