import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { TerminusModule } from '@nestjs/terminus';
import { TypeOrmModule } from '@nestjs/typeorm';

import { KmsController } from './controllers/kms.controller';
import { CryptographicKey } from './entities/cryptographic-key.entity';
import { KeyRotationLog } from './entities/key-rotation-log.entity';
import { CryptographicKeyRepository } from './repositories/cryptographic-key.repository';
import { KeyRotationLogRepository } from './repositories/key-rotation-log.repository';
import { CryptographicService } from './services/cryptographic.service';
import { JwksService } from './services/jwks.service';
import { KeyGenerationService } from './services/key-generation.service';
import { KeyRotationService } from './services/key-rotation.service';
import { KeyStorageService } from './services/key-storage.service';
import { KeyValidationService } from './services/key-validation.service';

@Module({
  imports: [
    ConfigModule,
    ScheduleModule.forRoot(),
    TerminusModule,
    TypeOrmModule.forFeature([CryptographicKey, KeyRotationLog]),
  ],
  controllers: [KmsController],
  providers: [
    KeyGenerationService,
    KeyRotationService,
    KeyStorageService,
    CryptographicService,
    JwksService,
    CryptographicKeyRepository,
    KeyRotationLogRepository,
    KeyValidationService,
  ],
  exports: [
    CryptographicService,
    JwksService,
    CryptographicKeyRepository,
    KeyRotationLogRepository,
  ],
})
export class KmsModule {}
