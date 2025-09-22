import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { TypeOrmModule } from '@nestjs/typeorm';

import { LoggerModule } from 'nestjs-pino';

import { databaseConfig } from '@/config/database.config';
import { pinoConfig } from '@/config/logger.config';
import { throttlerConfig } from '@/config/throttler.config';
import { CacheModule } from '@/shared/services/cache/cache.module';

@Module({
  imports: [
    // Config
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    // Database
    TypeOrmModule.forRootAsync(databaseConfig),

    // Cache
    CacheModule,

    // Logger
    LoggerModule.forRoot(pinoConfig),

    // Throttling
    ThrottlerModule.forRootAsync(throttlerConfig),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
