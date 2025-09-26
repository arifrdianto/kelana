import { createHash } from 'crypto';

import { Controller, Get, Header, HttpCode, Logger, Post, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';

import type { Request, Response } from 'express';

import {
  JWKSUnavailableException,
  JWKValidationException,
} from '@/shared/exceptions/jwk.exception';

import { JWKS } from '../interfaces/jwk.interface';
import { JwksService } from '../services/jwks.service';
import { KeyRotationService } from '../services/key-rotation.service';

@ApiTags('KMS')
@Controller('.well-known')
export class KmsController {
  private readonly logger = new Logger(KmsController.name);

  constructor(
    private readonly jwksService: JwksService,
    private readonly keyRotationService: KeyRotationService,
  ) {}

  @Get('jwks.json')
  @Throttle({ default: { limit: 100, ttl: 60000 } })
  @ApiOperation({
    summary: 'Get JSON Web Key Set (JWKS)',
    description: 'Returns active public keys for JWT verification',
  })
  @ApiResponse({ status: 200, description: 'JWKS response' })
  @ApiResponse({ status: 304, description: 'Not modified (cached)' })
  @ApiResponse({ status: 503, description: 'Service unavailable' })
  @Header('Content-Type', 'application/json; charset=utf-8')
  async getJwks(@Req() req: Request, @Res() res: Response): Promise<void> {
    try {
      const jwks = await this.jwksService.getJwks();

      this.setSecurityHeaders(res);

      const maxAge = 300;
      res.setHeader('Cache-Control', `public, max-age=${maxAge}, must-revalidate`);
      res.setHeader('Pragma', 'cache');

      const etag = this.generateJwksETag(jwks);
      res.setHeader('ETag', etag);

      if (req.headers['if-none-match'] === etag) {
        res.status(304).end();
        return;
      }

      if (jwks.keys.length === 0) {
        this.logger.warn('JWKS endpoint returning empty key set');
      }

      res.status(200).json(jwks);
    } catch (error) {
      // CHANGE: Handle specific exception types
      if (error instanceof JWKSUnavailableException) {
        this.logger.error('JWKS unavailable:', error.message);
        res.status(503).json({
          error: 'jwks_unavailable',
          error_description: error.message,
        });
        return;
      }

      if (error instanceof JWKValidationException) {
        this.logger.error('JWKS validation failed:', error.message);
        res.status(500).json({
          error: 'jwks_validation_failed',
          error_description: 'Key validation errors occurred',
        });
        return;
      }

      this.logger.error('Error serving JWKS', error);

      res.status(503).json({
        error: 'service_unavailable',
        error_description: 'Key service temporarily unavailable',
      });
    }
  }

  // Add these helper methods to the controller:

  private setSecurityHeaders(res: Response): void {
    // Prevent JWKS from being embedded in frames
    res.setHeader('X-Frame-Options', 'DENY');

    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Referrer policy for privacy
    res.setHeader('Referrer-Policy', 'no-referrer');

    // CORS headers for JWKS (typically need to be accessible cross-origin)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Accept, Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
  }

  private generateJwksETag(jwks: JWKS): string {
    const hash = createHash('sha256');
    hash.update(JSON.stringify(jwks, Object.keys(jwks).sort()));
    return `"${hash.digest('hex').substring(0, 16)}"`;
  }

  @Post('rotate-keys')
  @HttpCode(204)
  @ApiBearerAuth()
  async rotateKeys(): Promise<void> {
    this.logger.log('Manual key rotation requested');
    await this.keyRotationService.rotateKeys();
    this.logger.log('Manual key rotation completed successfully');
  }
}
