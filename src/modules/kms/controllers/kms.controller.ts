import {
  Controller,
  Get,
  Header,
  HttpCode,
  Logger,
  Post,
  Res,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';

import type { Response } from 'express';

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
  @Header('Cache-Control', 'public, max-age=60, immutable')
  async getJwks(@Res() res: Response): Promise<void> {
    try {
      const jwks = await this.jwksService.getJwks();

      if (jwks.keys.length === 0) {
        this.logger.warn('JWKS endpoint called but no valid keys available');
      }

      // Add cache headers
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=300, must-revalidate'); // 5 min
      res.setHeader('Pragma', 'cache');

      // Optional: strong ETag for caching validation
      const etag = `"${Buffer.from(JSON.stringify(jwks)).toString('base64url')}"`;
      res.setHeader('ETag', etag);

      res.status(200).json(jwks);
    } catch (error) {
      this.logger.error('Error serving JWKS', error);
      throw new ServiceUnavailableException('No valid keys available');
    }
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
