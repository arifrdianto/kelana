import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import KeyvRedis from '@keyv/redis';
import { Cacheable } from 'cacheable';
import Keyv from 'keyv';

@Module({
  providers: [
    {
      provide: 'CACHE_INSTANCE',
      useFactory: (configService: ConfigService) => {
        const redisUrl = configService.get<string>('REDIS_URL') || 'redis://localhost:6379';
        const ttl = parseInt(configService.get<string>('REDIS_TTL', '600'), 10) * 1000;

        const redisStore = new KeyvRedis(redisUrl);
        const store = new Keyv({
          store: redisStore,
          namespace: 'cache',
        });

        redisStore.on('error', (err) => {
          console.error('Redis store error:', err);
        });

        redisStore.on('connect', () => {
          console.log('Connected to Redis cache store');
        });

        redisStore.on('ready', () => {
          console.log('Redis cache store ready');
        });

        store.on('error', (err) => {
          console.error('Keyv store error:', err);
        });

        return new Cacheable({
          secondary: store,
          ttl,
        });
      },
      inject: [ConfigService],
    },
  ],
  exports: ['CACHE_INSTANCE'],
})
export class CacheModule {}
