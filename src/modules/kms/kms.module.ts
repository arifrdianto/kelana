import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { TerminusModule } from '@nestjs/terminus';
import { TypeOrmModule } from '@nestjs/typeorm';

import { CryptographicKey } from './entities/cryptographic-key.entity';
import { KeyRotationLog } from './entities/key-rotation-log.entity';
import { CryptographicKeyRepository } from './repositories/cryptographic-key.repository';
import { KeyRotationLogRepository } from './repositories/key-rotation-log.repository';
import { CryptographicService } from './services/cryptographic.service';
import { JwksService } from './services/jwks.service';
import { KeyGenerationService } from './services/key-generation.service';
import { KeyRotationService } from './services/key-rotation.service';
import { KeyStorageService } from './services/key-storage.service';
import { KmsController } from './kms.controller';

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
  ],
  exports: [
    CryptographicService,
    JwksService,
    CryptographicKeyRepository,
    KeyRotationLogRepository,
  ],
})
export class KmsModule {}
