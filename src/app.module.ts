import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { TypeOrmModule } from '@nestjs/typeorm';

import { LoggerModule } from 'nestjs-pino';

import { databaseConfig } from '@/config/database.config';
import { pinoConfig } from '@/config/logger.config';
import { throttlerConfig } from '@/config/throttler.config';
import { CacheModule } from '@/shared/services/cache/cache.module';

import { KmsModule } from './modules/kms/kms.module';

@Module({
  imports: [
    // Config
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    // Database (conditional - only if DATABASE_HOST is available)
    ...(process.env.DATABASE_HOST ? [TypeOrmModule.forRootAsync(databaseConfig)] : []),

    // Cache
    CacheModule,

    // Logger
    LoggerModule.forRoot(pinoConfig),

    // Throttling
    ThrottlerModule.forRootAsync(throttlerConfig),

    // KMS Module
    KmsModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
