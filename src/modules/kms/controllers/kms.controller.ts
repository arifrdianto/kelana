import { Controller, Get, HttpCode, Logger, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import { JWKS } from '../interfaces/jwk.interface';
import { JwksService } from '../services/jwks.service';
import { KeyRotationService } from '../services/key-rotation.service';
import { KeyStorageService } from '../services/key-storage.service';

@ApiTags('KMS')
@Controller('.well-known')
export class KmsController {
  private readonly logger = new Logger(KmsController.name);

  constructor(
    private readonly jwksService: JwksService,
    private readonly keyRotationService: KeyRotationService,
    private readonly keyStorageService: KeyStorageService,
  ) {}

  @Get('jwks.json')
  @ApiOperation({
    summary: 'Get JSON Web Key Set (JWKS)',
    description:
      'Returns the JSON Web Key Set containing all active, non-expired public keys for JWT signature verification',
  })
  @ApiResponse({
    status: 200,
    description: 'Returns the JSON Web Key Set',
    schema: {
      type: 'object',
      properties: {
        keys: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              kty: { type: 'string', example: 'RSA' },
              use: { type: 'string', example: 'sig' },
              kid: { type: 'string', example: 'kid_1a2b3c4d_5e6f7g8h' },
              alg: { type: 'string', example: 'RS256' },
              n: { type: 'string', description: 'Base64url-encoded RSA modulus' },
              e: { type: 'string', description: 'Base64url-encoded RSA exponent' },
              key_ops: { type: 'array', items: { type: 'string' }, example: ['verify'] },
              exp: { type: 'number', description: 'Expiration timestamp' },
            },
            required: ['kty', 'use', 'kid', 'alg', 'n', 'e'],
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 503,
    description: 'Service temporarily unavailable - no valid keys found',
  })
  async getJwks(): Promise<JWKS> {
    try {
      const jwks = await this.jwksService.getJwks();

      // Log warning if no keys available
      if (jwks.keys.length === 0) {
        this.logger.warn('JWKS endpoint called but no valid keys available');
      }

      return jwks;
    } catch (error) {
      this.logger.error('Error serving JWKS', error);
      // Return empty JWKS rather than throwing to prevent service disruption
      return { keys: [] };
    }
  }

  @Get('health')
  @ApiOperation({
    summary: 'Health check for KMS service',
    description:
      'Returns the health status of the KMS service including key availability and expiration information',
  })
  @ApiResponse({
    status: 200,
    description: 'KMS service health information',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', enum: ['healthy', 'degraded', 'unhealthy'] },
        activeKeys: { type: 'number' },
        expiredKeys: { type: 'number' },
        nextExpiry: { type: 'string', format: 'date-time', nullable: true },
        oldestKey: { type: 'string', format: 'date-time', nullable: true },
        jwksStats: {
          type: 'object',
          properties: {
            totalKeys: { type: 'number' },
            validKeys: { type: 'number' },
            certificateKeys: { type: 'number' },
          },
        },
      },
    },
  })
  async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    activeKeys: number;
    expiredKeys: number;
    nextExpiry?: Date;
    oldestKey?: Date;
    jwksStats: {
      totalKeys: number;
      validKeys: number;
      certificateKeys: number;
    };
  }> {
    try {
      const [keyHealth, jwksStats] = await Promise.all([
        this.keyStorageService.getKeyHealth(),
        this.jwksService.getJwksStats(),
      ]);

      // Determine health status
      let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

      if (keyHealth.activeKeys === 0) {
        status = 'unhealthy';
      } else if (keyHealth.activeKeys === 1 && keyHealth.nextExpiry) {
        // Check if the only key expires soon (within 7 days)
        const daysUntilExpiry = Math.ceil(
          (keyHealth.nextExpiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24),
        );
        if (daysUntilExpiry <= 7) {
          status = 'degraded';
        }
      }

      return {
        status,
        activeKeys: keyHealth.activeKeys,
        expiredKeys: keyHealth.expiredKeys,
        nextExpiry: keyHealth.nextExpiry,
        oldestKey: keyHealth.oldestKey,
        jwksStats: {
          totalKeys: jwksStats.totalKeys,
          validKeys: jwksStats.validKeys,
          certificateKeys: jwksStats.certificateKeys,
        },
      };
    } catch (error) {
      this.logger.error('Error in health check', error);
      return {
        status: 'unhealthy',
        activeKeys: 0,
        expiredKeys: 0,
        jwksStats: {
          totalKeys: 0,
          validKeys: 0,
          certificateKeys: 0,
        },
      };
    }
  }

  @Post('rotate-keys')
  @HttpCode(204)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Manually trigger key rotation',
    description:
      'Forces immediate key rotation. Use this endpoint for emergency key rotation or manual key management.',
  })
  @ApiResponse({
    status: 204,
    description: 'Key rotation initiated successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Authentication required',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @ApiResponse({
    status: 500,
    description: 'Internal server error - Key rotation failed',
  })
  async rotateKeys(): Promise<void> {
    try {
      this.logger.log('Manual key rotation requested');
      await this.keyRotationService.rotateKeys();
      this.logger.log('Manual key rotation completed successfully');
    } catch (error) {
      this.logger.error('Manual key rotation failed', error);
      throw error;
    }
  }

  @Get('stats')
  @ApiOperation({
    summary: 'Get KMS statistics',
    description: 'Returns detailed statistics about key management operations and service health',
  })
  @ApiResponse({
    status: 200,
    description: 'KMS statistics',
    schema: {
      type: 'object',
      properties: {
        keyHealth: {
          type: 'object',
          properties: {
            activeKeys: { type: 'number' },
            expiredKeys: { type: 'number' },
            nextExpiry: { type: 'string', format: 'date-time', nullable: true },
            oldestKey: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        jwksStats: {
          type: 'object',
          properties: {
            totalKeys: { type: 'number' },
            validKeys: { type: 'number' },
            expiredKeys: { type: 'number' },
            certificateKeys: { type: 'number' },
          },
        },
        rotationStats: {
          type: 'object',
          properties: {
            totalRotations: { type: 'number' },
            lastRotation: { type: 'string', format: 'date-time', nullable: true },
            nextScheduledCheck: { type: 'string', format: 'date-time' },
          },
        },
      },
    },
  })
  async getStats(): Promise<{
    keyHealth: any;
    jwksStats: any;
    rotationStats: any;
  }> {
    try {
      const [keyHealth, jwksStats, rotationStats] = await Promise.all([
        this.keyStorageService.getKeyHealth(),
        this.jwksService.getJwksStats(),
        this.keyRotationService.getRotationStats(),
      ]);

      return {
        keyHealth,
        jwksStats,
        rotationStats,
      };
    } catch (error) {
      this.logger.error('Error retrieving KMS statistics', error);
      throw error;
    }
  }
}
