import { Controller, Get, Logger } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import { JwksService } from './services/jwks.service';
import { JWKS } from './services/jwks.service';

@ApiTags('KMS')
@Controller('.well-known')
export class KmsController {
  private readonly logger = new Logger(KmsController.name);

  constructor(
    private readonly jwksService: JwksService,
    // private readonly keyRotationService: KeyRotationService,
  ) {}

  @Get('jwks.json')
  @ApiOperation({ summary: 'Get JSON Web Key Set (JWKS)' })
  @ApiResponse({ status: 200, description: 'Returns the JSON Web Key Set' })
  async getJwks(): Promise<JWKS> {
    return this.jwksService.getJwks();
  }

  // @Post('rotate-keys')
  // @HttpCode(204)
  // @ApiBearerAuth()
  // @ApiOperation({ summary: 'Manually trigger key rotation' })
  // @ApiResponse({ status: 204, description: 'Key rotation initiated successfully' })
  // @ApiResponse({ status: 401, description: 'Unauthorized' })
  // @ApiResponse({ status: 403, description: 'Forbidden - Admin access required' })
  // async rotateKeys(): Promise<void> {
  //   await this.keyRotationService.rotateKeys();
  // }
}
